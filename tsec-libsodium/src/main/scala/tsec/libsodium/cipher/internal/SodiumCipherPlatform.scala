package tsec.libsodium.cipher.internal

import cats.effect.Sync
import tsec.libsodium.ScalaSodium
import tsec.libsodium.cipher._
import tsec.libsodium.cipher.SodiumCipherError._

private[tsec] trait SodiumCipherPlatform[A]
    extends SodiumKeyGenerator[A, SodiumKey]
    with SodiumAuthCipher[A]
    with SodiumCipherAlgebra[A, SodiumKey] {
  implicit val authCipher: SodiumAuthCipher[A] = this

  final def generateKeyUnsafe(implicit s: ScalaSodium): SodiumKey[A] = {
    val bytes = new Array[Byte](keyLength)
    s.randombytes_buf(bytes, keyLength)
    SodiumKey.is[A].coerce(bytes)
  }

  final def buildKeyUnsafe(key: Array[Byte])(implicit s: ScalaSodium): SodiumKey[A] =
    if (key.length != keyLength)
      throw CipherKeyError("Invalid key length")
    else
      SodiumKey[A](key)

  final def encrypt[F[_]](plainText: PlainText, key: SodiumKey[A])(
      implicit F: Sync[F],
      S: ScalaSodium
  ): F[SodiumCipherText[A]] = F.delay {
    val outArray = new Array[Byte](plainText.length + macLen)
    val nonce    = new Array[Byte](nonceLen)
    S.randombytes_buf(nonce, nonceLen)
    if (sodiumEncrypt(outArray, plainText, nonce, key) != 0)
      throw EncryptError("Invalid encryption Info")

    SodiumCipherText[A](outArray, nonce)
  }

  final def decrypt[F[_]](cipherText: SodiumCipherText[A], key: SodiumKey[A])(
      implicit F: Sync[F],
      S: ScalaSodium
  ): F[PlainText] = F.delay {
    val originalMessage = new Array[Byte](cipherText.content.length - macLen)
    if (sodiumDecrypt(originalMessage, cipherText, key) != 0)
      throw DecryptError("Invalid Decryption info")
    PlainText(originalMessage)
  }

  final def encryptDetached[F[_]](plainText: PlainText, key: SodiumKey[A])(
      implicit F: Sync[F],
      S: ScalaSodium
  ): F[(SodiumCipherText[A], AuthTag[A])] = F.delay {
    val outArray = new Array[Byte](plainText.length)
    val macOut   = new Array[Byte](macLen)
    val nonce    = new Array[Byte](nonceLen)
    S.randombytes_buf(nonce, nonceLen)
    if (sodiumEncryptDetached(outArray, macOut, plainText, nonce, key) != 0)
      throw EncryptError("Invalid encryption Info")

    (SodiumCipherText[A](outArray, nonce), AuthTag.is[A].coerce(macOut))
  }

  final def decryptDetached[F[_]](cipherText: SodiumCipherText[A], key: SodiumKey[A], authTag: AuthTag[A])(
      implicit F: Sync[F],
      S: ScalaSodium
  ): F[PlainText] = F.delay {
    val originalMessage = new Array[Byte](cipherText.content.length)
    if (sodiumDecryptDetached(originalMessage, cipherText, authTag, key) != 0)
      throw DecryptError("Invalid Decryption info")
    PlainText(originalMessage)
  }
}
