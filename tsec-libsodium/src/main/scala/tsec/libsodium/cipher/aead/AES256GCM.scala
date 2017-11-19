package tsec.libsodium.cipher.aead

import tsec.cipher.symmetric
import tsec.libsodium.ScalaSodium
import tsec.libsodium.ScalaSodium.{NullLongBytes, NullLongLong}
import tsec.libsodium.cipher.{AuthTag, SodiumAAD, SodiumCipherText, SodiumKey}
import tsec.libsodium.cipher.internal.SodiumAEADPlatform

sealed trait AES256GCM

object AES256GCM extends SodiumAEADPlatform[AES256GCM] {
  def algorithm: String = "AES256-GCM"
  val keyLength: Int    = ScalaSodium.crypto_aead_aes256gcm_KEYBYTES
  val nonceLen: Int     = ScalaSodium.crypto_aead_aes256gcm_NPUBBYTES
  val authTagLen: Int   = ScalaSodium.crypto_aead_aes256gcm_ABYTES

  private[tsec] def sodiumEncrypt(
      cout: Array[Byte],
      pt: symmetric.PlainText,
      nonce: Array[Byte],
      key: SodiumKey[AES256GCM]
  )(implicit S: ScalaSodium): Int =
    S.crypto_aead_aes256gcm_encrypt(
      cout,
      NullLongLong,
      pt.content,
      pt.content.length,
      NullLongBytes,
      0,
      NullLongBytes,
      nonce,
      key
    )

  private[tsec] def sodiumDecrypt(origOut: Array[Byte], ct: SodiumCipherText[AES256GCM], key: SodiumKey[AES256GCM])(
      implicit S: ScalaSodium
  ): Int = S.crypto_aead_aes256gcm_decrypt(
    origOut,
    NullLongLong,
    NullLongBytes,
    ct.content,
    ct.content.length,
    NullLongBytes,
    0,
    ct.iv,
    key
  )

  private[tsec] def sodiumEncryptAAD(
      cout: Array[Byte],
      pt: symmetric.PlainText,
      nonce: Array[Byte],
      key: SodiumKey[AES256GCM],
      aad: SodiumAAD
  )(implicit S: ScalaSodium): Int =
    S.crypto_aead_aes256gcm_encrypt(
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
      ct: SodiumCipherText[AES256GCM],
      key: SodiumKey[AES256GCM],
      aad: SodiumAAD
  )(implicit S: ScalaSodium): Int =
    S.crypto_aead_aes256gcm_decrypt(
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
      key: SodiumKey[AES256GCM],
      aad: SodiumAAD
  )(implicit S: ScalaSodium): Int =
    S.crypto_aead_aes256gcm_encrypt_detached(
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
      ct: SodiumCipherText[AES256GCM],
      tagIn: AuthTag[AES256GCM],
      key: SodiumKey[AES256GCM],
      aad: SodiumAAD
  )(implicit S: ScalaSodium): Int =
    S.crypto_aead_aes256gcm_decrypt_detached(
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
