package tsec.libsodium.cipher.aead

import tsec.ScalaSodium
import tsec.ScalaSodium.{NullLongBytes, NullLongLong}
import tsec.cipher.symmetric
import tsec.libsodium.cipher._
import tsec.libsodium.cipher.internal.SodiumAEADPlatform

sealed trait OriginalChacha20

object OriginalChacha20 extends SodiumAEADPlatform[OriginalChacha20] {
  val nonceLen: Int   = ScalaSodium.crypto_aead_chacha20poly1305_NPUBBYTES
  val authTagLen: Int = ScalaSodium.crypto_aead_chacha20poly1305_ABYTES
  val keyLength: Int  = ScalaSodium.crypto_aead_chacha20poly1305_KEYBYTES

  def algorithm: String = "Chacha20Poly1305"

  private[tsec] def sodiumEncryptAAD(
      cout: Array[Byte],
      pt: symmetric.PlainText,
      nonce: Array[Byte],
      key: SodiumKey[OriginalChacha20],
      aad: SodiumAAD
  )(implicit S: ScalaSodium): Int =
    S.crypto_aead_chacha20poly1305_encrypt(
      cout,
      NullLongLong,
      pt.content,
      pt.content.length,
      aad,
      aad.length,
      NullLongBytes,
      nonce,
      key
    )

  private[tsec] def sodiumDecryptAAD(
      origOut: Array[Byte],
      ct: SodiumCipherText[OriginalChacha20],
      key: SodiumKey[OriginalChacha20],
      aad: SodiumAAD
  )(implicit S: ScalaSodium): Int =
    S.crypto_aead_chacha20poly1305_decrypt(
      origOut,
      NullLongLong,
      NullLongBytes,
      ct.content,
      ct.content.length,
      aad,
      aad.length,
      ct.iv,
      key
    )

  private[tsec] def sodiumEncryptDetachedAAD(
      cout: Array[Byte],
      tagOut: Array[Byte],
      pt: symmetric.PlainText,
      nonce: Array[Byte],
      key: SodiumKey[OriginalChacha20],
      aad: SodiumAAD
  )(implicit S: ScalaSodium): Int =
    S.crypto_aead_chacha20poly1305_encrypt_detached(
      cout,
      tagOut,
      NullLongLong,
      pt.content,
      pt.content.length,
      aad,
      aad.length,
      NullLongBytes,
      nonce,
      key
    )

  private[tsec] def sodiumDecryptDetachedAAD(
      origOut: Array[Byte],
      ct: SodiumCipherText[OriginalChacha20],
      tagIn: AuthTag[OriginalChacha20],
      key: SodiumKey[OriginalChacha20],
      aad: SodiumAAD
  )(implicit S: ScalaSodium): Int =
    S.crypto_aead_chacha20poly1305_decrypt_detached(
      origOut,
      NullLongBytes,
      ct.content,
      ct.content.length,
      tagIn,
      aad,
      aad.length,
      ct.iv,
      key
    )

}
