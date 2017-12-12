package tsec.libsodium.cipher

final case class SodiumCipherText[A](content: RawCiphertext[A], nonce: CipherNonce[A])
