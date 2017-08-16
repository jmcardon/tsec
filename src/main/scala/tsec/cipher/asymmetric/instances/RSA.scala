package tsec.cipher.asymmetric.instances


sealed trait RSA
object RSA extends WithAsymmetricGenerator[RSA]("RSA")
