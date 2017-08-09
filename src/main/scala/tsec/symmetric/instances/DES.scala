package tsec.symmetric.instances

sealed trait DES
object DES extends WithSymmetricGenerator[DES]("DES")
