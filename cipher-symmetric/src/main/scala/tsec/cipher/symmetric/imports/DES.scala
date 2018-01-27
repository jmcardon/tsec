package tsec.cipher.symmetric.imports

sealed trait DES

object DES extends BlockCipherEV[DES]("DES", 8, 8)
