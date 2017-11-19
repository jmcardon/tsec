package tsec.libsodium.cipher.aead

import tsec.cipher.symmetric
import tsec.libsodium.ScalaSodium
import tsec.libsodium.cipher._
import tsec.libsodium.ScalaSodium.{NullLongBytes, NullLongLong}
import tsec.libsodium.cipher.internal._

sealed trait XChacha20IETF

object XChacha20IETF extends SodiumAEADPlatform[XChacha20IETF] {
  def algorithm: String = "XChacha20Poly1305IETF"

  val nonceLen: Int   = ScalaSodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  val authTagLen: Int = ScalaSodium.crypto_aead_xchacha20poly1305_ietf_ABYTES
  val keyLength: Int  = ScalaSodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES

  private[tsec] def sodiumEncryptAAD(
      cout: Array[Byte],
      pt: symmetric.PlainText,
      nonce: Array[Byte],
      key: SodiumKey[XChacha20IETF],
      aad: SodiumAAD
  )(implicit S: ScalaSodium): Int =
    S.crypto_aead_xchacha20poly1305_ietf_encrypt(
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
      ct: SodiumCipherText[XChacha20IETF],
      key: SodiumKey[XChacha20IETF],
      aad: SodiumAAD
  )(implicit S: ScalaSodium): Int =
    S.crypto_aead_xchacha20poly1305_ietf_decrypt(
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
      key: SodiumKey[XChacha20IETF],
      aad: SodiumAAD
  )(implicit S: ScalaSodium): Int =
    S.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
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
      ct: SodiumCipherText[XChacha20IETF],
      tagIn: AuthTag[XChacha20IETF],
      key: SodiumKey[XChacha20IETF],
      aad: SodiumAAD
  )(implicit S: ScalaSodium): Int =
    S.crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
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
