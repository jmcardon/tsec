package tsec.cipher.asymmetric.instances


sealed trait DSA1024
object DSA1024 extends WithAsymmetricGenerator[DSA2048]("DSA", 1024)
