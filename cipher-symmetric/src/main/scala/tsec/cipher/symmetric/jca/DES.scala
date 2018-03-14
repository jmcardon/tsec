package tsec.cipher.symmetric.jca

sealed trait DES

object DES extends BlockCipherEV[DES]("DES", 8, 8)
