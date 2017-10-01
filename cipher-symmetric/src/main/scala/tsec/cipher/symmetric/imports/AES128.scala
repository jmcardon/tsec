package tsec.cipher.symmetric.imports

sealed trait AES128
object AES128 extends WithSymmetricGenerator[AES128]("AES", 128)
