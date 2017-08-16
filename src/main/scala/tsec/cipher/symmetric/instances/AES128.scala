package tsec.cipher.symmetric.instances

sealed trait AES128
object AES128 extends WithSymmetricGenerator[AES128]("AES_128", 128)
