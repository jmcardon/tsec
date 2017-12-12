package tsec.internal

trait CryptoAEADConstants {

  val crypto_aead_aes256gcm_KEYBYTES = 32

  val crypto_aead_aes256gcm_NSECBYTES = 0

  val crypto_aead_aes256gcm_NPUBBYTES = 12

  val crypto_aead_aes256gcm_ABYTES = 16

  val crypto_aead_aes256gcm_MESSAGEBYTES_MAX = Long.MaxValue - crypto_aead_aes256gcm_ABYTES

}
