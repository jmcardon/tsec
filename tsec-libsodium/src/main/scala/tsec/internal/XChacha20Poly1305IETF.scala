package tsec.internal

import jnr.ffi.annotations.{In, Out}
import jnr.ffi.byref.LongLongByReference
import jnr.ffi.types.u_int64_t

trait XChacha20Poly1305IETF {

  def crypto_aead_xchacha20poly1305_ietf_encrypt(
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

  def crypto_aead_xchacha20poly1305_ietf_decrypt(
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

  def crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
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

  def crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
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

  def crypto_aead_xchacha20poly1305_ietf_keygen(@Out keyBytes: Array[Byte]): Int
}

trait XChacha20Poly1305IETFConstants {
  val crypto_aead_xchacha20poly1305_ietf_KEYBYTES = 32

  val crypto_aead_xchacha20poly1305_ietf_NSECBYTES = 0

  val crypto_aead_xchacha20poly1305_ietf_NPUBBYTES = 24

  val crypto_aead_xchacha20poly1305_ietf_ABYTES = 16

  val crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX = Long.MaxValue - crypto_aead_xchacha20poly1305_ietf_ABYTES
}
