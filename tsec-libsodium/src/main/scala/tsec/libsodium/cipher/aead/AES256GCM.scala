package tsec.libsodium.cipher.aead

import tsec.cipher.symmetric.core._
import tsec.libsodium.ScalaSodium
import tsec.libsodium.ScalaSodium.{NullPtrBytes, NullPtrInt}
import tsec.libsodium.cipher._
import tsec.libsodium.cipher.internal.SodiumAEADPlatform

sealed trait AES256GCM

object AES256GCM extends SodiumAEADPlatform[AES256GCM] {
  def algorithm: String = "AES256-GCM"
  val keyLength: Int    = ScalaSodium.crypto_aead_aes256gcm_KEYBYTES
  val nonceLen: Int     = ScalaSodium.crypto_aead_aes256gcm_NPUBBYTES
  val authTagLen: Int   = ScalaSodium.crypto_aead_aes256gcm_ABYTES

  private[tsec] def sodiumEncrypt(
      cout: Array[Byte],
      pt: PlainText,
      nonce: Array[Byte],
      key: SodiumKey[AES256GCM]
  )(implicit S: ScalaSodium): Int =
    S.crypto_aead_aes256gcm_encrypt(
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

  private[tsec] def sodiumDecrypt(origOut: Array[Byte], ct: CipherText[AES256GCM], key: SodiumKey[AES256GCM])(
      implicit S: ScalaSodium
  ): Int =
    S.crypto_aead_aes256gcm_decrypt(
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

  private[tsec] def sodiumEncryptDetached(
      cout: Array[Byte],
      tagOut: Array[Byte],
      pt: PlainText,
      nonce: Array[Byte],
      key: SodiumKey[AES256GCM]
  )(implicit S: ScalaSodium): Int =
    S.crypto_aead_aes256gcm_encrypt_detached(
      cout,
      tagOut,
      NullPtrInt,
      pt,
      pt.length,
      NullPtrBytes,
      0,
      NullPtrBytes,
      nonce,
      key
    )

  private[tsec] def sodiumDecryptDetached(
      origOut: Array[Byte],
      ct: CipherText[AES256GCM],
      tagIn: AuthTag[AES256GCM],
      key: SodiumKey[AES256GCM]
  )(implicit S: ScalaSodium): Int =
    S.crypto_aead_aes256gcm_decrypt_detached(
      origOut,
      NullPtrBytes,
      ct.content,
      ct.content.length,
      tagIn,
      NullPtrBytes,
      0,
      ct.nonce,
      key
    )

  private[tsec] def sodiumEncryptAAD(
      cout: Array[Byte],
      pt: PlainText,
      nonce: Array[Byte],
      key: SodiumKey[AES256GCM],
      aad: AAD
  )(implicit S: ScalaSodium): Int =
    S.crypto_aead_aes256gcm_encrypt(
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
      ct: CipherText[AES256GCM],
      key: SodiumKey[AES256GCM],
      aad: AAD
  )(implicit S: ScalaSodium): Int =
    S.crypto_aead_aes256gcm_decrypt(
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
      key: SodiumKey[AES256GCM],
      aad: AAD
  )(implicit S: ScalaSodium): Int =
    S.crypto_aead_aes256gcm_encrypt_detached(
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
      ct: CipherText[AES256GCM],
      tagIn: AuthTag[AES256GCM],
      key: SodiumKey[AES256GCM],
      aad: AAD
  )(implicit S: ScalaSodium): Int =
    S.crypto_aead_aes256gcm_decrypt_detached(
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
