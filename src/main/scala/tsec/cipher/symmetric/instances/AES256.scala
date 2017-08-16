package tsec.cipher.symmetric.instances

sealed trait AES256
object AES256 extends WithSymmetricGenerator[AES256]("AES_256", 256)
