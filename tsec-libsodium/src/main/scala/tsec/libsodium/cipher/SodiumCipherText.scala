package tsec.libsodium.cipher

final case class SodiumCipherText[A](content: Array[Byte], iv: Array[Byte])
