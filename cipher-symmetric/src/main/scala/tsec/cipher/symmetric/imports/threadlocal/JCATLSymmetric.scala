package tsec.cipher.symmetric.imports.threadlocal

import java.util.{ArrayDeque => JQueue}
import javax.crypto.{Cipher => JCipher}
import cats.syntax.either._
import tsec.cipher.common._
import tsec.cipher.symmetric._
import tsec.cipher.common.padding.Padding
import tsec.cipher.symmetric.SymmetricCipherAlgebra
import tsec.cipher.symmetric.imports.{SecretKey, SymmetricCipher}
import tsec.cipher.symmetric.mode._
import tsec.common.ErrorConstruct._

abstract class JCATLSymmetric[A, M, P](
    implicit algoTag: SymmetricCipher[A],
    modeSpec: CipherMode[M],
    paddingTag: Padding[P]
) extends SymmetricCipherAlgebra[Either[CipherError, ?], A, M, P, SecretKey] {

  type C = JCipher

  protected val local: ThreadLocal[JQueue[JCipher]]

  private def catchGen: Either[InstanceInitError, JCipher] =
    Either
      .catchNonFatal(JCipher.getInstance(s"${algoTag.algorithm}/${modeSpec.algorithm}/${paddingTag.algorithm}"))
      .mapError(InstanceInitError.apply)

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
      .mapError(InstanceInitError.apply)

  def replace(instance: JCipher): Either[DecryptError, Unit] =
    Right(local.get().add(instance))

  /** Stateful operations for internal use
    * Made private so as to not encourage any use of stateful operations
    * The only other option would be to defer these operations with something like IO, given they are stateful
    */
  protected[symmetric] def initEncryptor(
      e: JCipher,
      secretKey: SecretKey[A]
  ): Either[CipherKeyError, Unit] =
    Either
      .catchNonFatal({
        e.init(JCipher.ENCRYPT_MODE, SecretKey.toJavaKey[A](secretKey), ParameterSpec.toRepr[M](modeSpec.genIv))
      })
      .mapError(CipherKeyError.apply)

  protected[symmetric] def initDecryptor(
      decryptor: JCipher,
      key: SecretKey[A],
      iv: Array[Byte]
  ): Either[CipherKeyError, Unit] =
    Either
      .catchNonFatal({
        decryptor.init(
          JCipher.DECRYPT_MODE,
          SecretKey.toJavaKey[A](key),
          ParameterSpec.toRepr[M](modeSpec.buildIvFromBytes(iv))
        )
      })
      .mapError(CipherKeyError.apply)

  protected[symmetric] def setAAD(e: JCipher, aad: AAD): Either[CipherKeyError, Unit] =
    Either.catchNonFatal(e.updateAAD(aad.aad)).mapError(CipherKeyError.apply)

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
  ): Either[CipherError, CipherText[A, M, P]] =
    for {
      instance <- genInstance
      _        <- initEncryptor(instance, key)
      encrypted <- Either
        .catchNonFatal(instance.doFinal(plainText.content))
        .mapError(EncryptError.apply)
      iv <- Either.fromOption(Option(instance.getIV), IvError("No IV found"))
      _  <- replace(instance)
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
  ): Either[CipherError, CipherText[A, M, P]] =
    for {
      instance <- genInstance
      _        <- initEncryptor(instance, key)
      _        <- setAAD(instance, aad)
      encrypted <- Either
        .catchNonFatal(instance.doFinal(plainText.content))
        .mapError(EncryptError.apply)
      iv <- Either.fromOption(Option(instance.getIV), IvError("No IV found"))
      _  <- replace(instance)
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
  ): Either[CipherError, PlainText] =
    for {
      instance <- genInstance
      _        <- initDecryptor(instance, key, cipherText.iv)
      decrypted <- Either
        .catchNonFatal(instance.doFinal(cipherText.content))
        .mapError(DecryptError.apply)
      _ <- replace(instance)
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
  ): Either[CipherError, PlainText] =
    for {
      instance <- genInstance
      _        <- initDecryptor(instance, key, cipherText.iv)
      _        <- setAAD(instance, aad)
      decrypted <- Either
        .catchNonFatal(instance.doFinal(cipherText.content))
        .mapError(DecryptError.apply)
      _ <- replace(instance)
    } yield PlainText(decrypted)
}

object JCATLSymmetric {

  protected[imports] def getJCipherUnsafe[A, M, P](
      implicit algoTag: SymmetricCipher[A],
      modeSpec: CipherMode[M],
      paddingTag: Padding[P]
  ): JCipher = JCipher.getInstance(s"${algoTag.algorithm}/${modeSpec.algorithm}/${paddingTag.algorithm}")

  /** generate queue unsafe
    *
    * @param queueLen
    * @tparam A
    * @tparam M
    * @tparam P
    * @return
    */
  protected[imports] def genQueueUnsafe[A: SymmetricCipher, M: CipherMode, P: Padding](
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
    * All processing is done using thread-local instances, to guarantee no leaked instances
    * @param queueLen the length of the queue
    * @tparam A Symmetric Cipher Algorithm
    * @tparam M Mode of operation
    * @tparam P Padding mode
    * @return
    */
  def apply[A: SymmetricCipher, M: CipherMode, P: Padding](
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

  def genInstance[A: SymmetricCipher, M: CipherMode, P: Padding]
    : Either[NoSuchInstanceError.type, JCATLSymmetric[A, M, P]] = apply[A, M, P]()

  /** ┌(▀Ĺ̯▀)–︻╦╤─ "You will never get away with an unsafe instance!!"
    *
    *  ━╤╦︻⊂(▀¯▀)┐ "Watch me"
    *
    * @tparam A Symmetric Cipher Algorithm
    * @tparam M Mode of operation
    * @tparam P Padding mode
    * @return
    */
  def getCipherUnsafe[A: SymmetricCipher, M: CipherMode, P: Padding](queueLen: Int): JCATLSymmetric[A, M, P] = {
    val queue = genQueueUnsafe(queueLen)
    new JCATLSymmetric[A, M, P] {
      protected val local: ThreadLocal[JQueue[JCipher]] = new ThreadLocal[JQueue[JCipher]] {
        override def initialValue(): JQueue[JCipher] = queue
      }
    }
  }

}
