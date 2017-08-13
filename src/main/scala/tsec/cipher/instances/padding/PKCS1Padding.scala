package tsec.cipher.instances.padding

sealed trait PKCS1Padding
object PKCS1Padding extends WithPaddingTag[PKCS1Padding]("PKCS1Padding")
