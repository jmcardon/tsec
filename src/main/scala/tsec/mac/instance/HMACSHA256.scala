package tsec.mac.instance

/*
Digest size of Sha256 is 32 bytes
 */
case class HMACSHA256(signed: Array[Byte])
object HMACSHA256 extends WithMacSigningKey[HMACSHA256]("HmacSHA256", 32)
