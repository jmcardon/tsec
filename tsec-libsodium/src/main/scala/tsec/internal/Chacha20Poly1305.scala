package tsec.internal

import jnr.ffi.annotations.{In, Out}
import jnr.ffi.byref.LongLongByReference
import jnr.ffi.types.u_int64_t

trait Chacha20Poly1305 {

  def crypto_aead_chacha20poly1305_keygen(@Out keyBytes: Array[Byte]): Int

  def crypto_aead_chacha20poly1305_encrypt(
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

  def crypto_aead_chacha20poly1305_decrypt(
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

trait Chacha20Poly1305Constants {

  val crypto_aead_chacha20poly1305_KEYBYTES = 32

  val crypto_aead_chacha20poly1305_NPUBBYTES = 8

  val crypto_aead_chacha20poly1305_ABYTES = 16

}
