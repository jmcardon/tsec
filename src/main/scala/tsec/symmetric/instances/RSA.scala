package tsec.symmetric.instances

sealed trait RSA
object RSA extends WithSymmetricGenerator[RSA]("RSA")
