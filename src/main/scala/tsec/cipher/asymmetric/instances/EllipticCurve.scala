package tsec.cipher.asymmetric.instances


/**
  * https://docs.oracle.com/javase/8/docs/technotes/guides/security/SunProviders.html
  */
sealed trait EllipticCurve
object EllipticCurve extends WithAsymmetricGenerator[EllipticCurve]("EllipticCurve", 571)
