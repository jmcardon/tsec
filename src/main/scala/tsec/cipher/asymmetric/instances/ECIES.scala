package tsec.cipher.asymmetric.instances


/**
  * https://docs.oracle.com/javase/8/docs/technotes/guides/security/SunProviders.html
  */
sealed trait ECIES
object ECIES extends WithAsymmetricGenerator[ECIES]("ECIES", 571)
