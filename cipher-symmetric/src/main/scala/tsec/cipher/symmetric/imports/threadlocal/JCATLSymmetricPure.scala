package tsec.cipher.symmetric.imports.threadlocal

import java.util.{ArrayDeque => JQueue}
import javax.crypto.{Cipher => JCipher}

import cats.effect.IO
import tsec.cipher.common._
import tsec.cipher.common.mode.ModeKeySpec
import tsec.cipher.common.padding.Padding
import tsec.cipher.symmetric.core.SymmetricCipherAlgebra
import tsec.cipher.symmetric.imports.{SecretKey, SymmetricAlgorithm}
import tsec.core.QueueAlloc

sealed abstract class JCATLSymmetricPure[A, M, P](queueAlloc: QueueAlloc[JCipher])(
    implicit algoTag: SymmetricAlgorithm[A],
    modeSpec: ModeKeySpec[M],
    paddingTag: Padding[P]
) extends SymmetricCipherAlgebra[IO, A, M, P, SecretKey] {

  type C = JCipher

  def genInstance: IO[JCipher] = IO {
    val inst = queueAlloc.dequeue
    if (inst != null)
      inst
    else
      JCATLSymmetricPure.getJCipherUnsafe[A, M, P]
  }

  def replace(instance: JCipher): IO[Unit] =
    IO(queueAlloc.enqueue(instance))

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
      plainText: PlainText,
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
      plainText: PlainText,
      key: SecretKey[A],
      aad: AAD
  ) =
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
  ): IO[PlainText] =
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
  ) =
    for {
      instance  <- genInstance
      _         <- initDecryptor(instance, key, cipherText.iv)
      _         <- setAAD(instance, aad)
      decrypted <- IO(instance.doFinal(cipherText.content))
      _         <- replace(instance)
    } yield PlainText(decrypted)
}

object JCATLSymmetricPure {

  protected[imports] def getJCipherUnsafe[A, M, P](
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
  protected[imports] def genQueueUnsafe[A: SymmetricAlgorithm, M: ModeKeySpec, P: Padding](
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
  ): IO[JCATLSymmetricPure[A, M, P]] =
    for {
      tL <- IO(QueueAlloc(List.fill(queueLen)(JCATLSymmetricPure.getJCipherUnsafe[A, M, P])))
    } yield new JCATLSymmetricPure[A, M, P](tL) {}

}
