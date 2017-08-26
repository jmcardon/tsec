package tsec.cipher.asymmetric.instances

sealed trait RSA2048
object RSA2048 extends WithAsymmetricGenerator[RSA2048]("RSA", 2048)

