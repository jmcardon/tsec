package tsec.cipher.symmetric.imports.aead

import javax.crypto.{Cipher => JCipher}
import cats.syntax.either._
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.mode._
import tsec.cipher.symmetric.imports._
import tsec.cipher.common.padding.Padding
import tsec.cipher.symmetric.JSymmetricCipherAlgebra
import tsec.common.ErrorConstruct._

class JCAAEAD[A, M, P](
    implicit algoTag: AEADCipher[A],
    modeSpec: AEADMode[M],
    paddingTag: Padding[P]
) extends JSymmetricCipherAlgebra[Either[CipherError, ?], A, M, P, SecretKey] {

  type C = JCipher

  def genInstance: Either[CipherError, JCipher] =
    Either
      .catchNonFatal(JCipher.getInstance(s"${algoTag.algorithm}/${modeSpec.algorithm}/${paddingTag.algorithm}"))
      .mapError(InstanceInitError.apply)

  /** Stateful operations for internal use Made private so as to not encourage any use of stateful operations.
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

  /** End stateful ops  */
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
    } yield PlainText(decrypted)
}

object JCAAEAD {

  /** Attempt to initialize an instance of the cipher with the given type parameters
    * If the cipher doesn't exist/is not supported, it will return NoSuchIntanceError
    *
    * @tparam A Symmetric Cipher Algorithm
    * @tparam M Mode of operation
    * @tparam P Padding mode
    * @return
    */
  def apply[A: AEADCipher, M: AEADMode, P: Padding]: Either[NoSuchInstanceError.type, JCAAEAD[A, M, P]] = {
    val c = new JCAAEAD[A, M, P]
    c.genInstance.map(_ => c).leftMap(_ => NoSuchInstanceError)
  }

  implicit def genSym[A: AEADCipher, M: AEADMode, P: Padding]: Either[NoSuchInstanceError.type, JCAAEAD[A, M, P]] =
    apply[A, M, P]

  /** ┌(▀Ĺ̯▀)–︻╦╤─ "You will never get away with an unsafe instance!!"
    *
    *  ━╤╦︻⊂(▀¯▀)┐ "Watch me"
    *
    * @tparam A Symmetric Cipher Algorithm
    * @tparam M Mode of operation
    * @tparam P Padding mode
    * @return
    */
  def getCipherUnsafe[A: AEADCipher, M: AEADMode, P: Padding]: JCAAEAD[A, M, P] =
    new JCAAEAD[A, M, P]

}
