package tsec.cipher.symmetric.instances

sealed trait AESWrap
object AESWrap extends WithSymmetricGenerator[AESWrap]("AESWrap", 128)
