package tsec.cipher.symmetric.imports

sealed trait AES192
object AES192 extends WithAEADCipher[AES192]("AES", 192)
