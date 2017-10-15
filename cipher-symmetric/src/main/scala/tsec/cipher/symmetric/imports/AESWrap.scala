package tsec.cipher.symmetric.imports

sealed trait AESWrap
object AESWrap extends WithAEADCipher[AESWrap]("AESWrap", 128)
