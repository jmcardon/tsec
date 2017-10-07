package tsec.cipher.asymmetric.imports

sealed trait ECIES384
object ECIES384 extends WithAsymmetricECIESGenerator[ECIES384]("P-384", 384)
