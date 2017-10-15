package tsec.cipher.symmetric.imports

sealed trait DES
object DES extends WithAEADCipher[DES]("DES", 56)
