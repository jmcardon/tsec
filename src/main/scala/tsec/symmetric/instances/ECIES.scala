package tsec.symmetric.instances

sealed trait ECIES
object ECIES extends WithSymmetricGenerator[ECIES]("ECIES")
