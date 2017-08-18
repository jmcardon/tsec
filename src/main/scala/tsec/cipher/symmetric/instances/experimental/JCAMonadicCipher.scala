package tsec.cipher.symmetric.instances.experimental

import javax.crypto.{Cipher => JCipher}

import cats.Monad
import cats.effect.Sync
import cats.implicits._
import tsec.cipher.common._
import tsec.cipher.common.mode.ModeKeySpec
import tsec.cipher.symmetric.core.SymmetricCipherAlgebra
import tsec.cipher.symmetric.instances.{JEncryptionKey, SymmetricAlgorithm}
import java.util.{ArrayDeque => JQueue}


/*
Experimental
 */
abstract class JCAMonadicCipher[F[_]: Monad: Sync, A, M, P](
    implicit algoTag: SymmetricAlgorithm[A],
    modeSpec: ModeKeySpec[M],
    paddingTag: Padding[P]
) extends SymmetricCipherAlgebra[F, A, M, P, JEncryptionKey] {
  type C = JCipher

  protected val local: ThreadLocal[JQueue[JCipher]]

  def genInstance: F[JCipher] =
    Sync[F].delay{
      val tl = local.get()
      val inst = tl.poll()
      if(inst != null)
        inst
      else
        JCipher.getInstance(s"${algoTag.algorithm}/${modeSpec.algorithm}/${paddingTag.algorithm}")
    }

  private def replace(instance: JCipher): F[Boolean] = Sync[F].delay(local.get().add(instance))

  protected[symmetric] def initEncryptor(e: JCipher, secretKey: SecretKey[JEncryptionKey[A]]): F[Unit] =
    Sync[F].delay(e.init(JCipher.ENCRYPT_MODE, secretKey.key, modeSpec.genIv))

  protected[symmetric] def initDecryptor(
      decryptor: JCipher,
      key: SecretKey[JEncryptionKey[A]],
      iv: Array[Byte]
  ): F[Unit] =
    Sync[F].delay(decryptor.init(JCipher.DECRYPT_MODE, key.key, modeSpec.buildIvFromBytes(iv)))

  protected[symmetric] def setAAD(e: JCipher, aad: AAD): F[Unit] =
    Sync[F].delay(e.updateAAD(aad.aad))

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
      encrypted <- Sync[F].delay(instance.doFinal(plainText.content))
      iv        <- Sync[F].pure(Option(instance.getIV).fold(throw IvError("No Iv Found"))(f => f))
      _ <- replace(instance)
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
      encrypted <- Sync[F].delay(instance.doFinal(plainText.content))
      iv        <- Sync[F].pure(Option(instance.getIV).fold(throw IvError("No Iv Found"))(f => f))
      _ <- replace(instance)
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
      decrypted <- Sync[F].delay(instance.doFinal(cipherText.content))
      _ <- replace(instance)
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
      decrypted <- Sync[F].delay(instance.doFinal(cipherText.content))
      _ <- replace(instance)
    } yield PlainText(decrypted)
}