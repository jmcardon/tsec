package tsec.libsodium.cipher.aead

import tsec.cipher.symmetric
import tsec.libsodium.ScalaSodium
import tsec.libsodium.cipher._
import tsec.libsodium.cipher.internal.SodiumAEADPlatform
import tsec.libsodium.ScalaSodium.{NullLongBytes, NullLongLong}

sealed trait IETFChacha20

object IETFChacha20 extends SodiumAEADPlatform[IETFChacha20] {
  val nonceLen: Int   = ScalaSodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES
  val authTagLen: Int = ScalaSodium.crypto_aead_chacha20poly1305_ietf_ABYTES
  val keyLength: Int  = ScalaSodium.crypto_aead_chacha20poly1305_ietf_KEYBYTES

  def algorithm: String = "Chacha20Poly1305IETF"

  private[tsec] def sodiumEncryptAAD(
      cout: Array[Byte],
      pt: symmetric.PlainText,
      nonce: Array[Byte],
      key: SodiumKey[IETFChacha20],
      aad: SodiumAAD
  )(implicit S: ScalaSodium): Int =
    S.crypto_aead_chacha20poly1305_ietf_encrypt(
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
      ct: SodiumCipherText[IETFChacha20],
      key: SodiumKey[IETFChacha20],
      aad: SodiumAAD
  )(implicit S: ScalaSodium): Int =
    S.crypto_aead_chacha20poly1305_ietf_decrypt(
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
      key: SodiumKey[IETFChacha20],
      aad: SodiumAAD
  )(implicit S: ScalaSodium): Int =
    S.crypto_aead_chacha20poly1305_ietf_encrypt_detached(
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
      ct: SodiumCipherText[IETFChacha20],
      tagIn: AuthTag[IETFChacha20],
      key: SodiumKey[IETFChacha20],
      aad: SodiumAAD
  )(implicit S: ScalaSodium): Int =
    S.crypto_aead_chacha20poly1305_ietf_decrypt_detached(
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
