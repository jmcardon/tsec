package tsec.cipher.symmetric.imports

sealed trait AES128
object AES128 extends WithAEADCipher[AES128]("AES", 128)
