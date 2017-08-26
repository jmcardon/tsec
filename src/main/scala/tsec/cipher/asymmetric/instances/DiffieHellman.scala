package tsec.cipher.asymmetric.instances


sealed trait DiffieHellman
object DiffieHellman extends WithAsymmetricGenerator[DiffieHellman]("DiffieHellman", 1024)
