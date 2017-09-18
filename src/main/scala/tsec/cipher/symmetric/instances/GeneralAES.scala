package tsec.cipher.symmetric.instances

sealed trait GeneralAES
object GeneralAES extends WithSymmetricGenerator[GeneralAES]("AES", 128)
