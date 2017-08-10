package tsec.symmetric.instances

sealed trait GCM
object GCM extends WithSymmetricGenerator[GCM]("GCM")
