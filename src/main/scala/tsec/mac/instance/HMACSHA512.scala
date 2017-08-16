package tsec.mac.instance

sealed trait HMACSHA512
object HMACSHA512 extends WithMacSigningKey[HMACSHA512]("HmacSHA512", 64)
