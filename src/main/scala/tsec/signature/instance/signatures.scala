package tsec.signature.instance

case class MD2withRSA(content: Array[Byte])

object MD2withRSA extends WithSignature[MD2withRSA]("MD2withRSA")

case class MD5withRSA(content: Array[Byte])

object MD5withRSA extends WithSignature[MD5withRSA]("MD5withRSA")

case class SHA1withRSA(content: Array[Byte])

object SHA1withRSA extends WithSignature[SHA1withRSA]("SHA1withRSA")

case class SHA224withRSA(content: Array[Byte])

object SHA224withRSA extends WithSignature[SHA224withRSA]("SHA224withRSA")

case class SHA256withRSA(content: Array[Byte])

object SHA256withRSA extends WithSignature[SHA256withRSA]("SHA256withRSA")

case class SHA384withRSA(content: Array[Byte])

object SHA384withRSA extends WithSignature[SHA384withRSA]("SHA384withRSA")

case class SHA512withRSA(content: Array[Byte])

object SHA512withRSA extends WithSignature[SHA512withRSA]("SHA512withRSA")

case class SHA1withDSA(content: Array[Byte])

object SHA1withDSA extends WithSignature[SHA1withDSA]("SHA1withDSA")

case class SHA224withDSA(content: Array[Byte])

object SHA224withDSA extends WithSignature[SHA224withDSA]("SHA224withDSA")

case class SHA256withDSA(content: Array[Byte])

object SHA256withDSA extends WithSignature[SHA256withDSA]("SHA256withDSA")

case class NONEwithECDSA(content: Array[Byte])

object NONEwithECDSA extends WithSignature[NONEwithECDSA]("NONEwithECDSA")

case class SHA1withECDSA(content: Array[Byte])

object SHA1withECDSA extends WithSignature[SHA1withECDSA]("SHA1withECDSA")

case class SHA224withECDSA(content: Array[Byte])

object SHA224withECDSA extends WithSignature[SHA224withECDSA]("SHA224withECDSA")

case class SHA256withECDSA(content: Array[Byte])

object SHA256withECDSA extends WithSignature[SHA256withECDSA]("SHA256withECDSA")

case class SHA384withECDSA(content: Array[Byte])

object SHA384withECDSA extends WithSignature[SHA384withECDSA]("SHA384withECDSA")

case class SHA512withECDSA(content: Array[Byte])

object SHA512withECDSA extends WithSignature[SHA512withECDSA]("SHA512withECDSA")
