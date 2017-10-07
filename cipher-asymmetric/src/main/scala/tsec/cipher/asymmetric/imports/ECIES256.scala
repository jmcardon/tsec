package tsec.cipher.asymmetric.imports

sealed trait ECIES256
object ECIES256 extends WithAsymmetricECIESGenerator[ECIES256]("P-256", 256)
