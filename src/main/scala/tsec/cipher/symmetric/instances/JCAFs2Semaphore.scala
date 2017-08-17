package tsec.cipher.symmetric.instances

import cats._
import tsec.cipher.common._
import tsec.cipher.common.mode.ModeKeySpec
import tsec.cipher.symmetric.core.SymmetricCipherAlgebra
import javax.crypto.{Cipher => JCipher}
import cats.data.EitherT
import fs2.Stream
import cats.implicits._
import fs2.util.Async
import java.util.{ArrayDeque => Queue}

import fs2.async.mutable.Semaphore

class JCAFs2Semaphore[F[_]: Monad: Async, A, M, P](
    cipherQueue: Queue[JCipher],
    s: Semaphore[F],
    queueSize: Int
)(
    implicit algoTag: SymmetricAlgorithm[A],
    modeSpec: ModeKeySpec[M],
    paddingTag: Padding[P]
) extends SymmetricCipherAlgebra[F, A, M, P, JEncryptionKey] {
  type C = JCipher

  def genInstance: F[JCipher] = s.decrementBy(1).as(cipherQueue.poll())

  def replaceInstance(instance: JCipher): F[Unit] = s.incrementBy(1).as(cipherQueue.addLast(instance))

  protected[symmetric] def initEncryptor(e: JCipher, secretKey: SecretKey[JEncryptionKey[A]]): F[Unit] =
    Async[F].pure(e.init(JCipher.ENCRYPT_MODE, secretKey.key, modeSpec.genIv))

  protected[symmetric] def initDecryptor(
      decryptor: JCipher,
      key: SecretKey[JEncryptionKey[A]],
      iv: Array[Byte]
  ): F[Unit] =
    Async[F].delay(decryptor.init(JCipher.DECRYPT_MODE, key.key, modeSpec.buildIvFromBytes(iv)))

  protected[symmetric] def setAAD(e: JCipher, aad: AAD): F[Unit] =
    Async[F].delay(e.updateAAD(aad.aad))

  /**
    * Encrypt our plaintext with a tagged secret key
    *
    * @param plainText the plaintext to encrypt
    * @param key       the SecretKey to use
    * @return
    */
  def encrypt(plainText: PlainText[A, M, P], key: SecretKey[JEncryptionKey[A]]): F[CipherText[A, M, P]] =
    for {
      instance  <- genInstance
      _         <- initEncryptor(instance, key)
      encrypted <- Async[F].pure(instance.doFinal(plainText.content))
      iv        <- Async[F].pure(Option(instance.getIV).fold(throw IvError("No Iv Found"))(f => f))
      _         <- replaceInstance(instance)
    } yield CipherText(encrypted, iv)

  /**
    * Encrypt our plaintext using additional authentication parameters,
    * Primarily for GCM mode and CCM mode
    * Other modes will return a cipherError attempting this
    *
    * @param plainText the plaintext to encrypt
    * @param key       the SecretKey to use
    * @param aad       The additional authentication information
    * @return
    */
  def encryptAAD(plainText: PlainText[A, M, P], key: SecretKey[JEncryptionKey[A]], aad: AAD): F[CipherText[A, M, P]] =
    for {
      instance  <- genInstance
      _         <- initEncryptor(instance, key)
      _         <- setAAD(instance, aad)
      encrypted <- Async[F].delay(instance.doFinal(plainText.content))
      iv        <- Async[F].pure(Option(instance.getIV).fold(throw IvError("No Iv Found"))(f => f))
      _         <- replaceInstance(instance)
    } yield CipherText(encrypted, iv)

  /**
    * Decrypt our ciphertext
    *
    * @param cipherText the plaintext to encrypt
    * @param key        the SecretKey to use
    * @return
    */
  def decrypt(cipherText: CipherText[A, M, P], key: SecretKey[JEncryptionKey[A]]): F[PlainText[A, M, P]] =
    for {
      instance  <- genInstance
      _         <- initDecryptor(instance, key, cipherText.iv)
      decrypted <- Async[F].delay(instance.doFinal(cipherText.content))
      _         <- replaceInstance(instance)
    } yield PlainText(decrypted)

  /**
    * Decrypt our ciphertext using additional authentication parameters,
    * Primarily for GCM mode and CCM mode
    * Other modes will return a cipherError attempting this
    *
    * @param cipherText the plaintext to encrypt
    * @param key        the SecretKey to use
    * @param aad        The additional authentication information
    * @return
    */
  def decryptAAD(cipherText: CipherText[A, M, P], key: SecretKey[JEncryptionKey[A]], aad: AAD): F[PlainText[A, M, P]] =
    for {
      instance  <- genInstance
      _         <- initDecryptor(instance, key, cipherText.iv)
      _         <- setAAD(instance, aad)
      decrypted <- Async[F].delay(instance.doFinal(cipherText.content))
      _         <- replaceInstance(instance)
    } yield PlainText(decrypted)
}

object JCAFs2Semaphore {
  def genInstance[F[_]:Monad: Async, A, M, P](queueSize: Int)(
      implicit algoTag: SymmetricAlgorithm[A],
      modeSpec: ModeKeySpec[M],
      paddingTag: Padding[P]
  ): F[JCAFs2Semaphore[F, A, M, P]] = {
    val mkqueue: F[Queue[JCipher]] = {
      val nq: Queue[JCipher] = new Queue[JCipher](queueSize)
      Stream
        .repeatEval[F, JCipher](
          Async[F].pure(JCipher.getInstance(s"${algoTag.algorithm}/${modeSpec.algorithm}/${paddingTag.algorithm}"))
        )
        .take(queueSize)
        .map(f => nq.add(f))
        .map(_ => nq)
        .runLog
        .map(_.head)
    }
    for {
      q   <- mkqueue
      sem <- Semaphore[F](queueSize)
    } yield new JCAFs2Semaphore[F, A, M, P](q, sem, queueSize)
  }
}
