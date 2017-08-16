package tsec.mac.instance

/*
Digest size of sha1 is 20, at least
 */
sealed trait HMACSHA1
object HMACSHA1 extends WithMacSigningKey[HMACSHA1]("HmacSHA1", 20)
