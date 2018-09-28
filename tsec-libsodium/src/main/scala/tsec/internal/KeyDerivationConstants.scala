package tsec.internal

/**
  * https://github.com/jedisct1/libsodium/blob/master/src/libsodium/include/sodium/crypto_kdf_blake2b.h
  */
trait KeyDerivationConstants {
  val crypto_kdf_BYTES_MIN    = 16
  val crypto_kdf_BYTES_MAX    = 64
  val crypto_kdf_CONTEXTBYTES = 8
  val crypto_kdf_KEYBYTES     = 32

  val crypto_kdf_PRIMITIVE = "blake2b"
}
