package tsec.cipher.asymmetric.imports

sealed trait RSA4096
object RSA4096 extends WithAsymmetricGenerator[RSA4096]("RSA", 4096)