package tsec.cipher.symmetric.libsodium.aead

import tsec.ScalaSodium
import tsec.cipher.symmetric
import tsec.cipher.symmetric.libsodium.{AuthTag, SodiumAAD, SodiumCipherText, SodiumKey}
import tsec.cipher.symmetric.libsodium.internal.SodiumAEADPlatform

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
      null,
      pt.content,
      pt.content.length,
      aad,
      aad.length,
      null,
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
      null,
      null,
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
      null,
      pt.content,
      pt.content.length,
      aad,
      aad.length,
      null,
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
      null,
      ct.content,
      ct.content.length,
      tagIn,
      aad,
      aad.length,
      ct.iv,
      key
    )

}
