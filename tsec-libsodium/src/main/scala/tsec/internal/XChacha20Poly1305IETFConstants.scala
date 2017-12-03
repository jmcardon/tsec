package tsec.internal

/** Constants from both the aead encryption:
  * https://github.com/jedisct1/libsodium/blob/master/src/libsodium/include/sodium/crypto_aead_xchacha20poly1305.h
  *
  * as well as secretStream stuff:
  * https://github.com/jedisct1/libsodium/blob/master/src/libsodium/include/sodium/crypto_secretstream_xchacha20poly1305.h
  *
  */
trait XChacha20Poly1305IETFConstants {
  val crypto_aead_xchacha20poly1305_ietf_KEYBYTES = 32

  val crypto_aead_xchacha20poly1305_ietf_NSECBYTES = 0

  val crypto_aead_xchacha20poly1305_ietf_NPUBBYTES = 24

  val crypto_aead_xchacha20poly1305_ietf_ABYTES = 16

  val crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX = Long.MaxValue - crypto_aead_xchacha20poly1305_ietf_ABYTES

  val crypto_secretstream_xchacha20poly1305_ABYTES: Int = crypto_aead_xchacha20poly1305_ietf_ABYTES + 1

  val crypto_secretstream_xchacha20poly1305_HEADERBYTES: Int = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES

  val crypto_secretstream_xchacha20poly1305_KEYBYTES = crypto_aead_xchacha20poly1305_ietf_KEYBYTES

  val crypto_secretstream_xchacha20poly1305_TAG_MESSAGE = 0

  val crypto_secretstream_xchacha20poly1305_TAG_PUSH = 1

  val crypto_secretstream_xchacha20poly1305_TAG_REKEY = 2

  val crypto_secretstream_xchacha20poly1305_TAG_FINAL: Short = 3.toShort
}
