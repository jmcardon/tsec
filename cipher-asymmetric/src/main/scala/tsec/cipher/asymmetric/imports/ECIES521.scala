package tsec.cipher.asymmetric.imports

sealed trait ECIES521
object ECIES521 extends WithAsymmetricECIESGenerator[ECIES521]("P-521", 521)
