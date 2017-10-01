package tsec.cipher.symmetric.imports

sealed trait AESWrap
object AESWrap extends WithSymmetricGenerator[AESWrap]("AESWrap", 128)
