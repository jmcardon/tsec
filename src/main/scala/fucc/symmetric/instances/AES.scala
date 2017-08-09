package fucc.symmetric.instances

sealed trait AES
object AES extends WithSymmetricGenerator[AES]("AES")
