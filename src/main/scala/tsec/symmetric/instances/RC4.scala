package tsec.symmetric.instances

sealed trait RC4
object RC4 extends WithSymmetricGenerator[RC4]("RC4")
