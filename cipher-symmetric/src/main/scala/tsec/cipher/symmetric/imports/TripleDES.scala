package tsec.cipher.symmetric.imports

sealed trait TripleDES

object TripleDES extends BlockCipherEV[TripleDES]("DESede", 8, 24)
