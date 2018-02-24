package tsec.libsodium.cipher.aead

import tsec.cipher.symmetric.core._
import tsec.libsodium.ScalaSodium
import tsec.libsodium.cipher._
import tsec.libsodium.ScalaSodium.{NullPtrBytes, NullPtrInt}
import tsec.libsodium.cipher.internal.SodiumAEADPlatform

sealed trait OriginalChacha20

object OriginalChacha20 extends SodiumAEADPlatform[OriginalChacha20] {
  val nonceLen: Int   = ScalaSodium.crypto_aead_chacha20poly1305_NPUBBYTES
  val authTagLen: Int = ScalaSodium.crypto_aead_chacha20poly1305_ABYTES
  val keyLength: Int  = ScalaSodium.crypto_aead_chacha20poly1305_KEYBYTES

  def algorithm: String = "Chacha20Poly1305"

  private[tsec] def sodiumEncrypt(
      cout: Array[Byte],
      pt: PlainText,
      nonce: Array[Byte],
      key: SodiumKey[OriginalChacha20]
  )(implicit S: ScalaSodium): Int =
    S.crypto_aead_chacha20poly1305_encrypt(
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
      ct: CipherText[OriginalChacha20],
      key: SodiumKey[OriginalChacha20]
  )(implicit S: ScalaSodium): Int =
    S.crypto_aead_chacha20poly1305_decrypt(
      origOut,
      NullPtrInt,
      NullPtrBytes,
      ct.content,
      ct.content.length,
      NullPtrBytes,
      0,
      ct.nonce,
      key
    )

  private[tsec] def sodiumEncryptAAD(
      cout: Array[Byte],
      pt: PlainText,
      nonce: Array[Byte],
      key: SodiumKey[OriginalChacha20],
      aad: AAD
  )(implicit S: ScalaSodium): Int =
    S.crypto_aead_chacha20poly1305_encrypt(
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
      ct: CipherText[OriginalChacha20],
      key: SodiumKey[OriginalChacha20],
      aad: AAD
  )(implicit S: ScalaSodium): Int =
    S.crypto_aead_chacha20poly1305_decrypt(
      origOut,
      NullPtrInt,
      NullPtrBytes,
      ct.content,
      ct.content.length,
      aad,
      aad.length,
      ct.nonce,
      key
    )

  private[tsec] def sodiumEncryptDetachedAAD(
      cout: Array[Byte],
      tagOut: Array[Byte],
      pt: PlainText,
      nonce: Array[Byte],
      key: SodiumKey[OriginalChacha20],
      aad: AAD
  )(implicit S: ScalaSodium): Int =
    S.crypto_aead_chacha20poly1305_encrypt_detached(
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
      ct: CipherText[OriginalChacha20],
      tagIn: AuthTag[OriginalChacha20],
      key: SodiumKey[OriginalChacha20],
      aad: AAD
  )(implicit S: ScalaSodium): Int =
    S.crypto_aead_chacha20poly1305_decrypt_detached(
      origOut,
      NullPtrBytes,
      ct.content,
      ct.content.length,
      tagIn,
      aad,
      aad.length,
      ct.nonce,
      key
    )

}
