package tsec.internal

import jnr.ffi.annotations.{In, Out}
import jnr.ffi.byref.LongLongByReference
import jnr.ffi.types.u_int64_t

trait CryptoAEAD {

  /**
    * @return 1 if the current CPU supports the AES256-GCM implementation,
    *         and 0 if it doesn't.
    */
  def crypto_aead_aes256gcm_is_available: Int

  def crypto_aead_aes256gcm_encrypt(
      @Out ct: Array[Byte],
      @Out ctLen: LongLongByReference,
      @In msg: Array[Byte],
      @In @u_int64_t msgLen: Int,
      @In ad: Array[Byte],
      @In @u_int64_t adLen: Int,
      @In nsec: Array[Byte],
      @In npub: Array[Byte],
      @In key: Array[Byte]
  ): Int

  def crypto_aead_aes256gcm_decrypt(
      @Out msg: Array[Byte],
      @Out msgLen: LongLongByReference,
      @In nsec: Array[Byte],
      @In ct: Array[Byte],
      @In @u_int64_t ctLen: Int,
      @In ad: Array[Byte],
      @In @u_int64_t adLen: Int,
      @In npub: Array[Byte],
      @In key: Array[Byte]
  ): Int

  def crypto_aead_aes256gcm_encrypt_detached(
      @Out ct: Array[Byte],
      @Out mac: Array[Byte],
      @Out macLen: LongLongByReference,
      @In msg: Array[Byte],
      @In @u_int64_t msgLen: Int,
      @In ad: Array[Byte],
      @In @u_int64_t adLen: Int,
      @In nsec: Array[Byte],
      @In npub: Array[Byte],
      @In key: Array[Byte]
  ): Int

  def crypto_aead_aes256gcm_decrypt_detached(
      @Out msg: Array[Byte],
      @Out nsec: Array[Byte],
      @In ct: Array[Byte],
      @In @u_int64_t ctLen: Int,
      @In mac: Array[Byte],
      @In ad: Array[Byte],
      @In @u_int64_t adLen: Int,
      @In npub: Array[Byte],
      @In key: Array[Byte]
  ): Int

  def crypto_aead_aes256gcm_statebytes: Int

  def crypto_aead_aes256gcm_beforenm(@Out state: Array[Byte], @In key: Array[Byte]): Int

  def crypto_aead_aes256gcm_encrypt_afternm(
      @Out ct: Array[Byte],
      @Out ctLen: LongLongByReference,
      @In msg: Array[Byte],
      @In @u_int64_t msgLen: Int,
      @In ad: Array[Byte],
      @In @u_int64_t adLen: Int,
      @In nsec: Array[Byte],
      @In npub: Array[Byte],
      @In @Out state: Array[Byte]
  ): Int

  def crypto_aead_aes256gcm_decrypt_afternm(
      @Out ct: Array[Byte],
      @Out ctLen: LongLongByReference,
      @In msg: Array[Byte],
      @In @u_int64_t msgLen: Int,
      @In ad: Array[Byte],
      @In @u_int64_t adLen: Int,
      @In nsec: Array[Byte],
      @In npub: Array[Byte],
      @In @Out state: Array[Byte]
  ): Int

}

trait CryptoAEADConstants {

  val crypto_aead_aes256gcm_KEYBYTES = 32

  val crypto_aead_aes256gcm_NSECBYTES = 0

  val crypto_aead_aes256gcm_NPUBBYTES = 12

  val crypto_aead_aes256gcm_ABYTES = 16

  val crypto_aead_aes256gcm_MESSAGEBYTES_MAX = Long.MaxValue - crypto_aead_aes256gcm_ABYTES

}
