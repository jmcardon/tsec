package tsec.cipher.symmetric.instances

import cats.{Monad, MonadError}
import tsec.cipher.common._
import tsec.cipher.common.mode.ModeKeySpec
import tsec.cipher.symmetric.core.SymmetricCipherAlgebra
import javax.crypto.{Cipher => JCipher}
import cats.implicits._
import fs2.util.{Catchable, Suspendable}
import tsec.core.ErrorConstruct

class JCAMonadicCipher[F[_]: Monad: Catchable: Suspendable, A, M, P](
    implicit algoTag: SymmetricAlgorithm[A],
    modeSpec: ModeKeySpec[M],
    paddingTag: Padding[P]
) extends SymmetricCipherAlgebra[F, A, M, P, JEncryptionKey] {
  type C = JCipher

  def genInstance: F[JCipher] =
    Suspendable[F].delay(JCipher.getInstance(s"${algoTag.algorithm}/${modeSpec.algorithm}/${paddingTag.algorithm}"))

  protected[symmetric] def initEncryptor(e: JCipher, secretKey: SecretKey[JEncryptionKey[A]]): F[Unit] =
    Suspendable[F].delay(e.init(JCipher.ENCRYPT_MODE, secretKey.key, modeSpec.genIv))

  protected[symmetric] def initDecryptor(
      decryptor: JCipher,
      key: SecretKey[JEncryptionKey[A]],
      iv: Array[Byte]
  ): F[Unit] =
    Suspendable[F].delay(decryptor.init(JCipher.DECRYPT_MODE, key.key, modeSpec.buildIvFromBytes(iv)))

  protected[symmetric] def setAAD(e: JCipher, aad: AAD): F[Unit] =
    Suspendable[F].delay(e.updateAAD(aad.aad))

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
      encrypted <- Suspendable[F].delay(instance.doFinal(plainText.content))
      iv        <- Suspendable[F].pure(Option(instance.getIV).fold(throw IvError("No Iv Found"))(f => f))
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
      encrypted <- Suspendable[F].delay(instance.doFinal(plainText.content))
      iv        <- Suspendable[F].pure(Option(instance.getIV).fold(throw IvError("No Iv Found"))(f => f))
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
      decrypted <- Suspendable[F].delay(instance.doFinal(cipherText.content))
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
      decrypted <- Suspendable[F].delay(instance.doFinal(cipherText.content))
    } yield PlainText(decrypted)
}
