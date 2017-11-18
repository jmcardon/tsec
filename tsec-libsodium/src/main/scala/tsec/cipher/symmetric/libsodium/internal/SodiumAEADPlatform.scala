package tsec.cipher.symmetric.libsodium.internal

import cats.effect.Sync
import tsec.{ScalaSodium => Sodium}
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.libsodium._

trait SodiumAEADPlatform[A]
    extends SodiumKeyGenerator[A, SodiumKey]
    with SodiumAEADCipher[A]
    with SodiumAEADAlgebra[A, SodiumKey] {

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

  def encryptAAD[F[_]](plaintext: PlainText, key: SodiumKey[A], aad: SodiumAAD)(
      implicit F: Sync[F],
      S: Sodium
  ): F[SodiumCipherText[A]] = F.delay {
    val outArray = new Array[Byte](plaintext.content.length + authTagLen)
    val nonce    = new Array[Byte](nonceLen)
    S.randombytes_buf(nonce, nonceLen)

    if (sodiumEncryptAAD(outArray, plaintext, nonce, key, aad) != 0)
      throw EncryptError("Invalid encryption Info")

    SodiumCipherText[A](outArray, nonce)
  }

  def decryptAAD[F[_]](cipherText: SodiumCipherText[A], key: SodiumKey[A], aad: SodiumAAD)(
      implicit F: Sync[F],
      S: Sodium
  ): F[PlainText] = F.delay {
    val originalMessage = new Array[Byte](cipherText.content.length - authTagLen)
    if (sodiumDecryptAAD(originalMessage, cipherText, key, aad) != 0)
      throw DecryptError("Invalid Decryption info")
    PlainText(originalMessage)
  }

  def encryptAADDetached[F[_]](plainText: PlainText, key: SodiumKey[A], aad: SodiumAAD)(
      implicit F: Sync[F],
      S: Sodium
  ): F[(SodiumCipherText[A], AuthTag[A])] = F.delay {
    val outArray = new Array[Byte](plainText.content.length)
    val macOut   = new Array[Byte](authTagLen)
    val nonce    = new Array[Byte](nonceLen)
    S.randombytes_buf(nonce, nonceLen)
    if (sodiumEncryptDetachedAAD(
          outArray,
          macOut,
          plainText,
          nonce,
          key,
          aad
        ) != 0)
      throw EncryptError("Invalid encryption Info")

    (SodiumCipherText[A](outArray, nonce), AuthTag.is[A].coerce(macOut))
  }

  def decryptAADDetached[F[_]](cipherText: SodiumCipherText[A], key: SodiumKey[A], authTag: AuthTag[A], aad: SodiumAAD)(
      implicit F: Sync[F],
      S: Sodium
  ): F[PlainText] = F.delay {
    val originalMessage = new Array[Byte](cipherText.content.length)
    if (sodiumDecryptDetachedAAD(
          originalMessage,
          cipherText,
          authTag,
          key,
          aad
        ) != 0)
      throw DecryptError("Invalid Decryption info")
    PlainText(originalMessage)
  }
}
