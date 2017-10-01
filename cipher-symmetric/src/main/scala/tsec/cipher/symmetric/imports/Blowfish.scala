package tsec.cipher.symmetric.imports

sealed trait Blowfish
object Blowfish extends WithSymmetricGenerator[Blowfish]("Blowfish", 448)
