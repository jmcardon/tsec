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
  * https://github.com/jedisct1/libsodium/blob/master/src/libsodium/include/sodium/crypto_shorthash_siphash24.h
  */
private[tsec] trait ShortHash {

  def crypto_shorthash_keygen(@Out key: Array[Byte]): Unit

  def crypto_shorthash_siphash24(
      @Out out: Array[Byte],
      @In in: Array[Byte],
      @In @u_int64_t inlen: Int,
      @In k: Array[Byte]
  ): Int

  def crypto_shorthash_siphashx24(
      @Out out: Array[Byte],
      @In in: Array[Byte],
      @In @u_int64_t inlen: Int,
      @In k: Array[Byte]
  )
}

private[tsec] trait ShortHashConstants {

  val crypto_shorthash_siphash24_BYTES = 8

  val crypto_shorthash_siphash24_KEYBYTES = 16

  val crypto_shorthash_siphashx24_BYTES = 16

  val crypto_shorthash_siphashx24_KEYBYTES = 16

}
