package tsec.cipher.symmetric.imports.aead

import cats.effect.Sync
import javax.crypto.{Cipher => JCipher}
import tsec.cipher.symmetric.mode._
import tsec.cipher.common.padding.Padding
import java.util.concurrent.{ConcurrentLinkedQueue => JQueue}
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.imports._
import cats.syntax.all._

class JCAAEADPure[F[_], A, M, P](queue: JQueue[JCipher])(
    implicit algoTag: AEADCipher[A],
    modeSpec: AEADMode[M],
    paddingTag: Padding[P],
    F: Sync[F]
) extends SymmetricCipherAlgebra[F, A, M, P, SecretKey] {

  type C = JCipher

  def genInstance: F[JCipher] = F.delay {
    val inst = queue.poll()
    if (inst != null)
      inst
    else
      JCAAEADPure.getJCipherUnsafe[A, M, P]
  }

  def replace(instance: JCipher): F[Boolean] =
    F.delay(queue.add(instance))

  /** We defer the effects of the encryption/decryption initialization */
  protected[symmetric] def initEncryptor(
      instance: JCipher,
      secretKey: SecretKey[A]
  ): F[Unit] =
    F.delay(
      instance.init(JCipher.ENCRYPT_MODE, SecretKey.toJavaKey[A](secretKey), ParameterSpec.toRepr[M](modeSpec.genIv))
    )

  protected[symmetric] def initDecryptor(
      instance: JCipher,
      key: SecretKey[A],
      iv: Array[Byte]
  ): F[Unit] =
    F.delay(
      instance
        .init(
          JCipher.DECRYPT_MODE,
          SecretKey.toJavaKey[A](key),
          ParameterSpec.toRepr[M](modeSpec.buildIvFromBytes(iv))
        )
    )

  protected[symmetric] def setAAD(e: JCipher, aad: AAD): F[Unit] =
    F.delay(e.updateAAD(aad.aad))

  /** End stateful ops */
  /** Encrypt our plaintext with a tagged secret key
    *
    * @param plainText the plaintext to encrypt
    * @param key the SecretKey to use
    * @return
    */
  def encrypt(
      plainText: PlainText,
      key: SecretKey[A]
  ) =
    for {
      instance  <- genInstance
      _         <- initEncryptor(instance, key)
      encrypted <- F.delay(instance.doFinal(plainText.content))
      iv        <- F.delay(instance.getIV)
      _         <- replace(instance)
    } yield CipherText(encrypted, iv)

  /** Encrypt our plaintext using additional authentication parameters,
    * Primarily for GCM mode and CCM mode
    * Other modes will return a cipherError attempting this
    *
    * @param plainText the plaintext to encrypt
    * @param key the SecretKey to use
    * @param aad The additional authentication information
    * @return
    */
  def encryptAAD(
      plainText: PlainText,
      key: SecretKey[A],
      aad: AAD
  ): F[CipherText[A, M, P]] =
    for {
      instance  <- genInstance
      _         <- initEncryptor(instance, key)
      _         <- setAAD(instance, aad)
      encrypted <- F.delay(instance.doFinal(plainText.content))
      iv        <- F.delay(instance.getIV)
      _         <- replace(instance)
    } yield CipherText(encrypted, iv)

  /** Decrypt our ciphertext
    *
    * @param cipherText the plaintext to encrypt
    * @param key the SecretKey to use
    * @return
    */
  def decrypt(
      cipherText: CipherText[A, M, P],
      key: SecretKey[A]
  ): F[PlainText] =
    for {
      instance  <- genInstance
      _         <- initDecryptor(instance, key, cipherText.iv)
      decrypted <- F.delay(instance.doFinal(cipherText.content))
      _         <- replace(instance)
    } yield PlainText(decrypted)

  /** Decrypt our ciphertext using additional authentication parameters,
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
      key: SecretKey[A],
      aad: AAD
  ): F[PlainText] =
    for {
      instance  <- genInstance
      _         <- initDecryptor(instance, key, cipherText.iv)
      _         <- setAAD(instance, aad)
      decrypted <- F.delay(instance.doFinal(cipherText.content))
      _         <- replace(instance)
    } yield PlainText(decrypted)
}

object JCAAEADPure {

  protected[imports] def getJCipherUnsafe[A, M, P](
      implicit algoTag: AEADCipher[A],
      modeSpec: AEADMode[M],
      paddingTag: Padding[P]
  ): JCipher = JCipher.getInstance(s"${algoTag.algorithm}/${modeSpec.algorithm}/${paddingTag.algorithm}")

  /** generate Queue unsafe
    *
    * @param queueLen
    * @tparam A
    * @tparam M
    * @tparam P
    * @return
    */
  protected[imports] def genQueueUnsafe[A: AEADCipher, M: AEADMode, P: Padding](
      queueLen: Int
  ): JQueue[JCipher] = {
    val q = new JQueue[JCipher]()
    (0 until queueLen)
      .foreach(
        _ => q.add(getJCipherUnsafe)
      )
    q
  }

  /** Attempt to initialize an instance of the cipher with the given type parameters
    * All processing is done on threadlocal, to guarantee no leaked instances
    * @param queueLen the length of the queue
    * @tparam A Symmetric Cipher Algorithm
    * @tparam M Mode of operation
    * @tparam P Padding mode
    * @return
    */
  def apply[F[_], A: AEADCipher, M: AEADMode, P: Padding](
      queueLen: Int = 15
  )(implicit F: Sync[F]): F[JCAAEADPure[F, A, M, P]] =
    for {
      q <- F.delay(genQueueUnsafe(queueLen))
    } yield new JCAAEADPure[F, A, M, P](q) {}

  implicit def genInstance[F[_]: Sync, A: AEADCipher, M: AEADMode, P: Padding]: F[JCAAEADPure[F, A, M, P]] =
    apply[F, A, M, P]()

}
