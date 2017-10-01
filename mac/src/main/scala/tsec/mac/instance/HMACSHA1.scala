package tsec.mac.instance

/*
Digest size of sha1 is 20, at least
 */
case class HMACSHA1(signed: Array[Byte])

object HMACSHA1 extends WithMacSigningKey[HMACSHA1]("HmacSHA1", 20)
