package tsec.cipher.symmetric.imports

sealed trait AES256
object AES256 extends WithAEADCipher[AES256]("AES", 256)
