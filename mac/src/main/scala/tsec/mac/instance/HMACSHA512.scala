package tsec.mac.instance

case class HMACSHA512(signed: Array[Byte])

object HMACSHA512 extends WithMacSigningKey[HMACSHA512]("HmacSHA512", 64)
