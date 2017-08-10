package tsec.symmetric.instances

sealed trait RC5
object RC5 extends WithSymmetricGenerator[RC5]("RC5")
