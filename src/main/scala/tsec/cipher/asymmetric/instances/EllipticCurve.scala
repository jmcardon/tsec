package tsec.cipher.asymmetric.instances


sealed trait EllipticCurve
object EllipticCurve extends WithAsymmetricGenerator[EllipticCurve]("EllipticCurve")
