package tsec.mac.instance

case class HMACSHA384(signed: Array[Byte])

object HMACSHA384 extends WithMacSigningKey[HMACSHA384]("HmacSHA384", 48)
