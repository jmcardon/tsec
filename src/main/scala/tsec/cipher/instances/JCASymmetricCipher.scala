package tsec.cipher.instances

import javax.crypto.{Cipher => JCipher}

import cats.syntax.either._
import tsec.cipher.core._
import tsec.symmetric.core.SymmetricAlgorithm
import tsec.symmetric.instances.JEncryptionKey

class JCASymmetricCipher[A, M, P](
    implicit algoTag: SymmetricAlgorithm[A],
    modeSpec: ModeKeySpec[M],
    paddingTag: Padding[P]
) extends SymmetricCipherAlgebra[Either[CipherError, ?], A, M, P, JEncryptionKey] {

  type C = JCipher

  def genInstance: Either[CipherError, JCipher] =
    Either
      .catchNonFatal(JCipher.getInstance(s"${algoTag.algorithm}/${modeSpec.algorithm}/${paddingTag.algorithm}"))
      .leftMap(e => InstanceInitError.apply(e.getMessage))

  /*
  Stateful operations for internal use
  Made private so as to not encourage any use of stateful operations
  The only other option would be to defer these operations with something like IO, given they are stateful
   */
  private def initEncryptor(e: JCipher, secretKey: SecretKey[JEncryptionKey[A]]): Either[KeyError, Unit] =
    Either
      .catchNonFatal({
        e.init(JCipher.ENCRYPT_MODE, secretKey.key)
      })
      .leftMap(e => KeyError(e.getMessage))

  private def initDecryptor(
      decryptor: JCipher,
      key: SecretKey[JEncryptionKey[A]],
      iv: Array[Byte]
  ): Either[KeyError, Unit] =
    Either
      .catchNonFatal({
        decryptor.init(JCipher.DECRYPT_MODE, key.key, modeSpec.buildAlgorithmSpec(iv))
      })
      .leftMap(e => KeyError(e.getMessage))

  private def setAAD(e: JCipher, aad: AAD): Either[KeyError, Unit] =
    Either.catchNonFatal(e.updateAAD(aad.aad)).leftMap(e => KeyError(e.getMessage))
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
      instance  <- genInstance
      _         <- initEncryptor(instance, key)
      encrypted <- Either.catchNonFatal(instance.doFinal(plainText.content)).leftMap(e => EncryptError(e.getMessage))
      iv        <- Either.fromOption(Option(instance.getIV), IvError("No IV found"))
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
      instance  <- genInstance
      _         <- initEncryptor(instance, key)
      _         <- setAAD(instance, aad)
      encrypted <- Either.catchNonFatal(instance.doFinal(plainText.content)).leftMap(e => EncryptError(e.getMessage))
      iv        <- Either.fromOption(Option(instance.getIV), IvError("No IV found"))
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
      instance  <- genInstance
      _         <- initDecryptor(instance, key, cipherText.iv)
      decrypted <- Either.catchNonFatal(instance.doFinal(cipherText.content)).leftMap(e => DecryptError(e.getMessage))
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
      instance  <- genInstance
      _         <- initDecryptor(instance, key, cipherText.iv)
      _         <- setAAD(instance, aad)
      decrypted <- Either.catchNonFatal(instance.doFinal(cipherText.content)).leftMap(e => DecryptError(e.getMessage))
    } yield PlainText(decrypted)
}

object JCASymmetricCipher {

  /**
    * Attempt to initialize an instance of the cipher with the given type parameters
    * If the cipher doesn't exist/is not supported, it will return NoSuchIntanceError
    *
    * @tparam A Symmetric Cipher Algorithm
    * @tparam M Mode of operation
    * @tparam P Padding mode
    * @return
    */
  def getCipher[A: SymmetricAlgorithm, M: ModeKeySpec, P: Padding]
    : Either[NoSuchInstanceError, JCASymmetricCipher[A, M, P]] = {
    val c = new JCASymmetricCipher[A, M, P]
    c.genInstance.map(_ => c).leftMap(_ => NoSuchInstanceError)
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
  def getCipherUnsafe[A: SymmetricAlgorithm, M: ModeKeySpec, P: Padding]: JCASymmetricCipher[A, M, P] =
    new JCASymmetricCipher[A, M, P]
}
