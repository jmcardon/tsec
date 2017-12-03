package tsec.libsodium.cipher.aead

import tsec.libsodium.ScalaSodium
import tsec.libsodium.cipher._
import tsec.libsodium.ScalaSodium.{NullPtrBytes, NullPtrInt}
import tsec.libsodium.cipher.internal._

sealed trait XChacha20IETF

object XChacha20IETF extends SodiumAEADPlatform[XChacha20IETF] {
  def algorithm: String = "XChacha20Poly1305IETF"

  val nonceLen: Int   = ScalaSodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  val authTagLen: Int = ScalaSodium.crypto_aead_xchacha20poly1305_ietf_ABYTES
  val keyLength: Int  = ScalaSodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES

  private[tsec] def sodiumEncrypt(
      cout: Array[Byte],
      pt: PlainText,
      nonce: Array[Byte],
      key: SodiumKey[XChacha20IETF]
  )(implicit S: ScalaSodium): Int =
    S.crypto_aead_xchacha20poly1305_ietf_encrypt(
      cout,
      NullPtrInt,
      pt,
      pt.length,
      NullPtrBytes,
      0,
      NullPtrBytes,
      nonce,
      key
    )

  private[tsec] def sodiumDecrypt(
      origOut: Array[Byte],
      ct: SodiumCipherText[XChacha20IETF],
      key: SodiumKey[XChacha20IETF]
  )(implicit S: ScalaSodium): Int =
    S.crypto_aead_xchacha20poly1305_ietf_decrypt(
      origOut,
      NullPtrInt,
      NullPtrBytes,
      ct.content,
      ct.content.length,
      NullPtrBytes,
      0,
      ct.iv,
      key
    )

  private[tsec] def sodiumEncryptAAD(
      cout: Array[Byte],
      pt: PlainText,
      nonce: Array[Byte],
      key: SodiumKey[XChacha20IETF],
      aad: SodiumAAD
  )(implicit S: ScalaSodium): Int =
    S.crypto_aead_xchacha20poly1305_ietf_encrypt(
      cout,
      NullPtrInt,
      pt,
      pt.length,
      aad,
      aad.length,
      NullPtrBytes,
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
      NullPtrInt,
      NullPtrBytes,
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
      pt: PlainText,
      nonce: Array[Byte],
      key: SodiumKey[XChacha20IETF],
      aad: SodiumAAD
  )(implicit S: ScalaSodium): Int =
    S.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
      cout,
      tagOut,
      NullPtrInt,
      pt,
      pt.length,
      aad,
      aad.length,
      NullPtrBytes,
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
      NullPtrBytes,
      ct.content,
      ct.content.length,
      tagIn,
      aad,
      aad.length,
      ct.iv,
      key
    )

}
