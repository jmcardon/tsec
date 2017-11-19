package tsec.internal

/**
  * https://github.com/jedisct1/libsodium/blob/master/src/libsodium/include/sodium/crypto_generichash_blake2b.h
  */
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
