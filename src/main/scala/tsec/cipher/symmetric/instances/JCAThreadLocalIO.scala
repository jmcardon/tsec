package tsec.cipher.symmetric.instances

import javax.crypto.{Cipher => JCipher}

import cats.implicits._
import tsec.cipher.common._
import tsec.cipher.common.mode.ModeKeySpec
import tsec.cipher.symmetric.core.SymmetricCipherAlgebra
import tsec.core.ErrorConstruct
import java.util.{ArrayDeque => JQueue}

import cats.effect.IO

abstract class JCAThreadLocalIO[A, M, P](queue: JQueue[JCipher])(
    implicit algoTag: SymmetricAlgorithm[A],
    modeSpec: ModeKeySpec[M],
    paddingTag: Padding[P]
) extends SymmetricCipherAlgebra[IO, A, M, P, JEncryptionKey] {

  type C = JCipher

  /*
  This is a stateful optimization
  `.getInstance` is expensive as all hell. There's almost no point in doing this constantly.
   */

  protected val local: ThreadLocal[JQueue[JCipher]]

  private def catchGen: IO[JCipher] =
    IO(JCipher.getInstance(s"${algoTag.algorithm}/${modeSpec.algorithm}/${paddingTag.algorithm}"))

  def genInstance: IO[JCipher] = {
    val threadLocal = local.get()
    val inst        = threadLocal.poll()
    if (inst == null)
      catchGen
    else
      IO.pure(inst)
  }

  def replace(instance: JCipher): IO[Unit] =
    IO(local.get().addLast(instance))

  /*
  Stateful operations for internal use
  Made private so as to not encourage any use of stateful operations
  The only other option would be to defer these operations with something like IO, given they are stateful
   */
  protected[symmetric] def initEncryptor(
      e: JCipher,
      secretKey: SecretKey[JEncryptionKey[A]]
  ) =
    IO(e.init(JCipher.ENCRYPT_MODE, secretKey.key, modeSpec.genIv))

  protected[symmetric] def initDecryptor(
      decryptor: JCipher,
      key: SecretKey[JEncryptionKey[A]],
      iv: Array[Byte]
  ): IO[Unit] =
    IO(decryptor.init(JCipher.DECRYPT_MODE, key.key, modeSpec.buildIvFromBytes(iv)))

  protected[symmetric] def setAAD(e: JCipher, aad: AAD): IO[Unit] =
    IO(e.updateAAD(aad.aad))
  /*
  End stateful ops
   */

  /**
    * Encrypt our plaintext with a tagged secret key
    *
    * @param plainText the plaintext to encrypt
    * @param key the SecretKey to use
    * @return
    */
  def encrypt(
      plainText: PlainText[A, M, P],
      key: SecretKey[JEncryptionKey[A]]
  ): IO[CipherText[A, M, P]] =
    for {
      instance  <- genInstance
      _         <- initEncryptor(instance, key)
      encrypted <- IO(instance.doFinal(plainText.content))
      iv        <- IO(instance.getIV)
      _         <- replace(instance)
    } yield CipherText(encrypted, iv)

  /**
    * Encrypt our plaintext using additional authentication parameters,
    * Primarily for GCM mode and CCM mode
    * Other modes will return a cipherError attempting this
    *
    * @param plainText the plaintext to encrypt
    * @param key the SecretKey to use
    * @param aad The additional authentication information
    * @return
    */
  def encryptAAD(
      plainText: PlainText[A, M, P],
      key: SecretKey[JEncryptionKey[A]],
      aad: AAD
  ): IO[CipherText[A, M, P]] =
    for {
      instance  <- genInstance
      _         <- initEncryptor(instance, key)
      _         <- setAAD(instance, aad)
      encrypted <- IO(instance.doFinal(plainText.content))
      iv        <- IO(instance.getIV)
      _         <- replace(instance)
    } yield CipherText(encrypted, iv)

  /**
    * Decrypt our ciphertext
    *
    * @param cipherText the plaintext to encrypt
    * @param key the SecretKey to use
    * @return
    */
  def decrypt(
      cipherText: CipherText[A, M, P],
      key: SecretKey[JEncryptionKey[A]]
  ): IO[PlainText[A, M, P]] =
    for {
      instance  <- genInstance
      _         <- initDecryptor(instance, key, cipherText.iv)
      decrypted <- IO(instance.doFinal(cipherText.content))
      _         <- replace(instance)
    } yield PlainText(decrypted)

  /**
    * Decrypt our ciphertext using additional authentication parameters,
    * Primarily for GCM mode and CCM mode
    * Other modes will return a cipherError attempting this
    *
    * @param cipherText the plaintext to encrypt
    * @param key the SecretKey to use
    * @param aad The additional authentication information
    * @return
    */
  def decryptAAD(
      cipherText: CipherText[A, M, P],
      key: SecretKey[JEncryptionKey[A]],
      aad: AAD
  ): IO[PlainText[A, M, P]] =
    for {
      instance  <- genInstance
      _         <- initDecryptor(instance, key, cipherText.iv)
      _         <- setAAD(instance, aad)
      decrypted <- IO(instance.doFinal(cipherText.content))
      _         <- replace(instance)
    } yield PlainText(decrypted)
}

object JCAThreadLocalIO {

  protected[instances] def getJCipherUnsafe[A, M, P](
      implicit algoTag: SymmetricAlgorithm[A],
      modeSpec: ModeKeySpec[M],
      paddingTag: Padding[P]
  ): JCipher = JCipher.getInstance(s"${algoTag.algorithm}/${modeSpec.algorithm}/${paddingTag.algorithm}")

  /**
    *
    *
    * @param queueLen
    * @tparam A
    * @tparam M
    * @tparam P
    * @return
    */
  protected[instances] def genQueueUnsafe[A: SymmetricAlgorithm, M: ModeKeySpec, P: Padding](
      queueLen: Int
  ): JQueue[JCipher] = {
    val q = new JQueue[JCipher](queueLen)
    (0 until queueLen)
      .foreach(
        _ => q.addLast(getJCipherUnsafe)
      )
    q
  }


  /**
    * Attempt to initialize an instance of the cipher with the given type parameters
    * All processing is done on threadlocal, to guarantee no leaked instances
    * @param queueLen the length of the queue
    * @tparam A Symmetric Cipher Algorithm
    * @tparam M Mode of operation
    * @tparam P Padding mode
    * @return
    */
  def getCipher[A: SymmetricAlgorithm, M: ModeKeySpec, P: Padding](
      queueLen: Int = 15
  ): IO[JCAThreadLocalIO[A, M, P]] =
    for {
      q <- IO(genQueueUnsafe(queueLen))
      tL <- IO({
        val t = new ThreadLocal[JQueue[JCipher]]
        t.set(q)
        t
      })
    } yield
      new JCAThreadLocalIO[A, M, P](q) {
        protected val local: ThreadLocal[JQueue[JCipher]] = tL
      }

}
