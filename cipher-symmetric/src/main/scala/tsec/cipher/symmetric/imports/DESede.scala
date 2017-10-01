package tsec.cipher.symmetric.imports

sealed trait DESede
object DESede extends WithSymmetricGenerator[DESede]("DESede", 168)
