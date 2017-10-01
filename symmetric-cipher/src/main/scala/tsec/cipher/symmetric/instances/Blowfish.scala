package tsec.cipher.symmetric.instances

sealed trait Blowfish
object Blowfish extends WithSymmetricGenerator[Blowfish]("Blowfish", 448)
