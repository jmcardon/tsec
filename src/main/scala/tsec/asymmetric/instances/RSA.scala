package tsec.asymmetric.instances


sealed trait RSA
object RSA extends WithAsymmetricGenerator[RSA]("RSA")
