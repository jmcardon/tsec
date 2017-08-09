package fucc.symmetric.instances

sealed trait DES
object DES extends WithSymmetricGenerator[DES]("DES")
