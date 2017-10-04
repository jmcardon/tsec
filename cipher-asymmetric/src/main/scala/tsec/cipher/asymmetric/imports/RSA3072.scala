package tsec.cipher.asymmetric.imports

sealed trait RSA3072
object RSA3072 extends WithAsymmetricGenerator[RSA3072]("RSA", 3072)