package tsec.mac.instance

/*
Digest size of Sha256 is 32 bytes
 */
sealed trait HMACSHA256
object HMACSHA256 extends WithMacSigningKey[HMACSHA256]("HmacSHA256", 32)
