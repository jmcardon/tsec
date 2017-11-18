package tsec.cipher.symmetric.libsodium.internal

import cats.effect.Sync
import tsec.{ScalaSodium => Sodium}
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.libsodium._

private[tsec] trait SodiumCipherPlatform[A]
    extends SodiumKeyGenerator[A, SodiumKey]
    with SodiumAuthCipher[A]
    with SodiumCipherAlgebra[A, SodiumKey] {
  implicit val authCipher: SodiumAuthCipher[A] = this

  def generateKeyUnsafe(implicit s: Sodium): SodiumKey[A] = {
    val bytes = new Array[Byte](keyLength)
    s.randombytes_buf(bytes, keyLength)
    SodiumKey.is[A].coerce(bytes)
  }

  def buildKeyUnsafe(key: Array[Byte])(implicit s: Sodium): SodiumKey[A] =
    if (key.length != keyLength)
      throw CipherKeyError("Invalid key length")
    else
      SodiumKey[A](key)

  def encrypt[F[_]](plainText: PlainText, key: SodiumKey[A])(
      implicit F: Sync[F],
      S: Sodium
  ): F[SodiumCipherText[A]] = F.delay {
    val outArray = new Array[Byte](plainText.content.length + macLen)
    val nonce    = new Array[Byte](nonceLen)
    S.randombytes_buf(nonce, nonceLen)
    if (sodiumEncrypt(outArray, plainText, nonce, key) != 0)
      throw EncryptError("Invalid encryption Info")

    SodiumCipherText[A](outArray, nonce)
  }

  def decrypt[F[_]](cipherText: SodiumCipherText[A], key: SodiumKey[A])(
      implicit F: Sync[F],
      S: Sodium
  ): F[PlainText] = F.delay {
    val originalMessage = new Array[Byte](cipherText.content.length - macLen)
    if (sodiumDecrypt(originalMessage, cipherText, key) != 0)
      throw DecryptError("Invalid Decryption info")
    PlainText(originalMessage)
  }

  def encryptDetached[F[_]](plainText: PlainText, key: SodiumKey[A])(
      implicit F: Sync[F],
      S: Sodium
  ): F[(SodiumCipherText[A], AuthTag[A])] = F.delay {
    val outArray = new Array[Byte](plainText.content.length)
    val macOut   = new Array[Byte](macLen)
    val nonce    = new Array[Byte](nonceLen)
    S.randombytes_buf(nonce, nonceLen)
    if (sodiumEncryptDetached(outArray, macOut, plainText, nonce, key) != 0)
      throw EncryptError("Invalid encryption Info")

    (SodiumCipherText[A](outArray, nonce), AuthTag.is[A].coerce(macOut))
  }

  def decryptDetached[F[_]](cipherText: SodiumCipherText[A], key: SodiumKey[A], authTag: AuthTag[A])(
      implicit F: Sync[F],
      S: Sodium
  ): F[PlainText] = F.delay {
    val originalMessage = new Array[Byte](cipherText.content.length)
    if (sodiumDecryptDetached(originalMessage, cipherText, authTag, key) != 0)
      throw DecryptError("Invalid Decryption info")
    PlainText(originalMessage)
  }
}
