package tsec.cipher.symmetric.imports

sealed trait AES192
object AES192 extends WithSymmetricGenerator[AES192]("AES", 192)
