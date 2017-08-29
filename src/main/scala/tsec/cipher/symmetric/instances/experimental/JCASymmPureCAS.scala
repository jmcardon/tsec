package tsec.cipher.symmetric.instances.experimental

import java.util.concurrent.{ConcurrentLinkedQueue => JQueue}
import javax.crypto.{Cipher => JCipher}

import cats.effect.IO
import tsec.cipher.common._
import tsec.cipher.common.mode.ModeKeySpec
import tsec.cipher.symmetric.core.SymmetricCipherAlgebra
import tsec.cipher.symmetric.instances.{SecretKey, SymmetricAlgorithm}

sealed abstract class JCASymmPureCAS[A, M, P](queue: JQueue[JCipher])(
    implicit algoTag: SymmetricAlgorithm[A],
    modeSpec: ModeKeySpec[M],
    paddingTag: Padding[P]
) extends SymmetricCipherAlgebra[IO, A, M, P, SecretKey] {

  type C = JCipher

  /*
  This is our local optimization.
  Using threadLocal + fixed thread pool,
  you can abstract over
   */
  def genInstance: IO[JCipher] = IO {
    val inst = queue.poll()
    if (inst != null)
      inst
    else
      JCASymmPureCAS.getJCipherUnsafe[A, M, P]
  }

  def replace(instance: JCipher): IO[Unit] =
    IO(queue.add(instance))

  /*
  We defer the effects of the encryption/decryption initialization
   */
  protected[symmetric] def initEncryptor(
      instance: JCipher,
      secretKey: SecretKey[A]
  ): IO[Unit] =
    IO(instance.init(JCipher.ENCRYPT_MODE, secretKey.key, modeSpec.genIv))

  protected[symmetric] def initDecryptor(
      instance: JCipher,
      key: SecretKey[A],
      iv: Array[Byte]
  ): IO[Unit] =
    IO(instance.init(JCipher.DECRYPT_MODE, key.key, modeSpec.buildIvFromBytes(iv)))

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
      key: SecretKey[A]
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
      key: SecretKey[A],
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
      key: SecretKey[A]
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
      key: SecretKey[A],
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

object JCASymmPureCAS {

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
    val q = new JQueue[JCipher]()
    (0 until queueLen)
      .foreach(
        _ => q.add(getJCipherUnsafe)
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
  def apply[A: SymmetricAlgorithm, M: ModeKeySpec, P: Padding](
      queueLen: Int = 15
  ): IO[JCASymmPureCAS[A, M, P]] =
    for {
      q <- IO(genQueueUnsafe(queueLen))
    } yield new JCASymmPureCAS[A, M, P](q) {}

}
