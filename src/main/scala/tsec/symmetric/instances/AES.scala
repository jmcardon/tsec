package tsec.symmetric.instances

sealed trait AES
object AES extends WithSymmetricGenerator[AES]("AES")
