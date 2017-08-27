package tsec.cipher.asymmetric.instances


sealed trait DSA2048
object DSA2048 extends WithAsymmetricGenerator[DSA2048]("DSA", 2048)
