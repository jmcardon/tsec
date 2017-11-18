package tsec.cipher.symmetric.libsodium

final case class SodiumCipherText[A](content: Array[Byte], iv: Array[Byte])
