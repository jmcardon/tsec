package tsec.cipher.asymmetric.instances


sealed trait DSA
object DSA extends WithAsymmetricGenerator[DSA]("DSA")
