package tsec.cipher.symmetric.instances

sealed trait DES
object DES extends WithSymmetricGenerator[DES]("DES", 56)
