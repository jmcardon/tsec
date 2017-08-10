package tsec.symmetric.instances

sealed trait ARCFOUR
object ARCFOUR extends WithSymmetricGenerator[ARCFOUR]("ARCFOUR")
