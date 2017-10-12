package tsec.cipher.symmetric.imports

sealed trait Blowfish
object Blowfish extends WithAEADCipher[Blowfish]("Blowfish", 448)
