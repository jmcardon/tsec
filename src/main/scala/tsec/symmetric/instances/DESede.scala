package tsec.symmetric.instances

sealed trait DESede
object DESede extends WithSymmetricGenerator[DESede]("DESede", 168)
