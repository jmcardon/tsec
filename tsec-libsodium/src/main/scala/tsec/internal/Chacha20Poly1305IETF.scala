package tsec.internal

import jnr.ffi.annotations.{In, Out}
import jnr.ffi.byref.LongLongByReference
import jnr.ffi.types.u_int64_t

trait Chacha20Poly1305IETF {

  def crypto_aead_chacha20poly1305_ietf_keygen(@Out keyBytes: Array[Byte]): Int

  def crypto_aead_chacha20poly1305_ietf_encrypt(
      @Out ct: Array[Byte],
      @Out ctLength: LongLongByReference,
      @In message: Array[Byte],
      @In @u_int64_t messageLength: Int,
      @In additionalData: Array[Byte],
      @In @u_int64_t adLength: Int,
      @In nsec: Array[Byte],
      @In npub: Array[Byte],
      @In key: Array[Byte]
  ): Int

  def crypto_aead_chacha20poly1305_ietf_decrypt(
      @Out message: Array[Byte],
      @Out messageLength: LongLongByReference,
      @In nsec: Array[Byte],
      @In ct: Array[Byte],
      @In @u_int64_t ctLength: Int,
      @In additionalData: Array[Byte],
      @In @u_int64_t adLength: Int,
      @In npub: Array[Byte],
      @In key: Array[Byte]
  ): Int

}

trait Chacha20Poly1305IETFConstants {

  val crypto_aead_chacha20poly1305_ietf_KEYBYTES = 32L

  val crypto_aead_chacha20poly1305_ietf_NSECBYTES = 0L

  val crypto_aead_chacha20poly1305_ietf_NPUBBYTES = 12L

  val crypto_aead_chacha20poly1305_ietf_ABYTES = 16L

}
