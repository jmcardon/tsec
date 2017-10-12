package tsec.cipher.symmetric.imports

sealed trait DESede
object DESede extends WithAEADCipher[DESede]("DESede", 168)
