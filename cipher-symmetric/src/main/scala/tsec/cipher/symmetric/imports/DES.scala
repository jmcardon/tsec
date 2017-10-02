package tsec.cipher.symmetric.imports

sealed trait DES
object DES extends WithSymmetricGenerator[DES]("DES", 56)
