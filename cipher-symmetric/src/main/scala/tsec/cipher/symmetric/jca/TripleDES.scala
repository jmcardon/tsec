package tsec.cipher.symmetric.jca

sealed trait TripleDES

object TripleDES extends BlockCipherEV[TripleDES]("DESede", 8, 24)
