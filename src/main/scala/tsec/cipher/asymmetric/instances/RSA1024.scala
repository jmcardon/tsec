package tsec.cipher.asymmetric.instances


sealed trait RSA1024
object RSA1024 extends WithAsymmetricGenerator[RSA2048]("RSA", 1024)
