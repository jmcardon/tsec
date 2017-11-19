package tsec.internal

import cats.effect.Sync
import jnr.ffi.LibraryLoader
import jnr.ffi.Platform
import jnr.ffi.annotations.In
import jnr.ffi.annotations.Out
import jnr.ffi.byref.LongLongByReference
import jnr.ffi.types.u_int64_t
import jnr.ffi.types.u_int8_t
import jnr.ffi.types.size_t

/**
  * https://github.com/jedisct1/libsodium/blob/master/src/libsodium/include/sodium/crypto_generichash_blake2b.h
  */
private[tsec] trait GenericHash {

  def crypto_generichash(
      @Out out: Array[Byte],
      @In in: Array[Byte],
      @In @u_int64_t inLen: Int,
      @In key: Array[Byte],
      @In @size_t keyLen: Long
  )

  def crypto_generichash_blake2b(
      @Out out: Array[Byte],
      @In @size_t outLen: Long,
      @In int: Array[Byte],
      @In @u_int64_t inLen: Int,
      @In key: Array[Byte],
      @In @size_t keyLen: Long
  ): Int

}

private[tsec] trait GenericHashConstants {
  val crypto_generichash_blake2b_BYTES_MIN = 16

  val crypto_generichash_blake2b_BYTES_MAX = 64

  val crypto_generichash_blake2b_BYTES = 32

  val crypto_generichash_blake2b_KEYBYTES_MIN = 16

  val crypto_generichash_blake2b_KEYBYTES_MAX = 64

  val crypto_generichash_blake2b_KEYBYTES = 32

  val crypto_generichash_blake2b_SALTBYTES = 16

  val crypto_generichash_blake2b_PERSONALBYTES = 16
}
