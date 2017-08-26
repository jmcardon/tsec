package tsec.cipher.symmetric.instances.threadlocal

import java.util.{ArrayDeque => JQueue}
import javax.crypto.{Cipher => JCipher}

import cats.syntax.either._
import tsec.cipher.common._
import tsec.cipher.common.mode.ModeKeySpec
import tsec.cipher.symmetric.core.SymmetricCipherAlgebra
import tsec.cipher.symmetric.instances.{JEncryptionKey, SymmetricAlgorithm}
import tsec.core.ErrorConstruct

abstract class JCATLSymmetric[A, M, P](
    implicit algoTag: SymmetricAlgorithm[A],
    modeSpec: ModeKeySpec[M],
    paddingTag: Padding[P]
) extends SymmetricCipherAlgebra[Either[CipherError, ?], A, M, P, JEncryptionKey] {

  type C = JCipher

  protected val local: ThreadLocal[JQueue[JCipher]]

  private def catchGen: Either[InstanceInitError, JCipher] =
    Either
      .catchNonFatal(JCipher.getInstance(s"${algoTag.algorithm}/${modeSpec.algorithm}/${paddingTag.algorithm}"))
      .leftMap(ErrorConstruct.fromThrowable[InstanceInitError])

  def genInstance: Either[CipherError, JCipher] =
    Either
      .catchNonFatal {
        val threadLocal = local.get()
        threadLocal.poll()
      }
      .flatMap { inst =>
        if (inst == null)
          catchGen
        else
          Right(inst)
      }
      .leftMap(ErrorConstruct.fromThrowable[InstanceInitError])

  def replace(instance: JCipher): Either[DecryptError, Unit] =
    Right(local.get().add(instance))

  /*
  Stateful operations for internal use
  Made private so as to not encourage any use of stateful operations
  The only other option would be to defer these operations with something like IO, given they are stateful
   */
  protected[symmetric] def initEncryptor(
      e: JCipher,
      secretKey: SecretKey[JEncryptionKey[A]]
  ): Either[CipherKeyError, Unit] =
    Either
      .catchNonFatal({
        e.init(JCipher.ENCRYPT_MODE, secretKey.key, modeSpec.genIv)
      })
      .leftMap(ErrorConstruct.fromThrowable[CipherKeyError])

  protected[symmetric] def initDecryptor(
      decryptor: JCipher,
      key: SecretKey[JEncryptionKey[A]],
      iv: Array[Byte]
  ): Either[CipherKeyError, Unit] =
    Either
      .catchNonFatal({
        decryptor.init(JCipher.DECRYPT_MODE, key.key, modeSpec.buildIvFromBytes(iv))
      })
      .leftMap(ErrorConstruct.fromThrowable[CipherKeyError])

  protected[symmetric] def setAAD(e: JCipher, aad: AAD): Either[CipherKeyError, Unit] =
    Either.catchNonFatal(e.updateAAD(aad.aad)).leftMap(ErrorConstruct.fromThrowable[CipherKeyError])
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
  ): Either[CipherError, CipherText[A, M, P]] =
    for {
      instance <- genInstance
      _        <- initEncryptor(instance, key)
      encrypted <- Either
        .catchNonFatal(instance.doFinal(plainText.content))
        .leftMap(ErrorConstruct.fromThrowable[EncryptError])
      iv <- Either.fromOption(Option(instance.getIV), IvError("No IV found"))
      _  <- replace(instance)
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
  ): Either[CipherError, CipherText[A, M, P]] =
    for {
      instance <- genInstance
      _        <- initEncryptor(instance, key)
      _        <- setAAD(instance, aad)
      encrypted <- Either
        .catchNonFatal(instance.doFinal(plainText.content))
        .leftMap(ErrorConstruct.fromThrowable[EncryptError])
      iv <- Either.fromOption(Option(instance.getIV), IvError("No IV found"))
      _  <- replace(instance)
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
  ): Either[CipherError, PlainText[A, M, P]] =
    for {
      instance <- genInstance
      _        <- initDecryptor(instance, key, cipherText.iv)
      decrypted <- Either
        .catchNonFatal(instance.doFinal(cipherText.content))
        .leftMap(ErrorConstruct.fromThrowable[DecryptError])
      _ <- replace(instance)
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
  ): Either[CipherError, PlainText[A, M, P]] =
    for {
      instance <- genInstance
      _        <- initDecryptor(instance, key, cipherText.iv)
      _        <- setAAD(instance, aad)
      decrypted <- Either
        .catchNonFatal(instance.doFinal(cipherText.content))
        .leftMap(ErrorConstruct.fromThrowable[DecryptError])
      _ <- replace(instance)
    } yield PlainText(decrypted)
}

object JCATLSymmetric {

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
  def getCipher[A: SymmetricAlgorithm, M: ModeKeySpec, P: Padding](
      queueLen: Int = 15
  ): Either[NoSuchInstanceError.type, JCATLSymmetric[A, M, P]] =
    for {
      q <- Either.catchNonFatal(genQueueUnsafe(queueLen)).leftMap(_ => NoSuchInstanceError)
      tl <- Either
        .catchNonFatal {
          new ThreadLocal[JQueue[JCipher]] {
            override def initialValue(): JQueue[JCipher] =
              q
          }
        }
        .leftMap(_ => NoSuchInstanceError)
    } yield
      new JCATLSymmetric[A, M, P] {
        protected val local: ThreadLocal[JQueue[JCipher]] = tl
      }

  /**
    * ┌(▀Ĺ̯▀)–︻╦╤─ "You will never get away with an unsafe instance!!"
    *
    *  ━╤╦︻⊂(▀¯▀)┐ "Watch me"
    *
    * @tparam A Symmetric Cipher Algorithm
    * @tparam M Mode of operation
    * @tparam P Padding mode
    * @return
    */
  def getCipherUnsafe[A: SymmetricAlgorithm, M: ModeKeySpec, P: Padding](queueLen: Int): JCATLSymmetric[A, M, P] = {
    val queue = genQueueUnsafe(queueLen)
    new JCATLSymmetric[A, M, P] {
      protected val local: ThreadLocal[JQueue[JCipher]] = new ThreadLocal[JQueue[JCipher]] {
        override def initialValue(): JQueue[JCipher] = queue
      }
    }
  }

}
