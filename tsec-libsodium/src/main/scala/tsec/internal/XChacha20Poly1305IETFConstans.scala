package tsec.internal

trait XChacha20Poly1305IETFConstants {
  val crypto_aead_xchacha20poly1305_ietf_KEYBYTES = 32

  val crypto_aead_xchacha20poly1305_ietf_NSECBYTES = 0

  val crypto_aead_xchacha20poly1305_ietf_NPUBBYTES = 24

  val crypto_aead_xchacha20poly1305_ietf_ABYTES = 16

  val crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX = Long.MaxValue - crypto_aead_xchacha20poly1305_ietf_ABYTES
}
