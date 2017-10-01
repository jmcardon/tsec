package tsec.cipher.symmetric.imports

sealed trait AES256
object AES256 extends WithSymmetricGenerator[AES256]("AES", 256)
