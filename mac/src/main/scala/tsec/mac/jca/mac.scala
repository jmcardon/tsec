package tsec.mac.jca

sealed trait HMACSHA1

object HMACSHA1 extends WithMacSigningKey[HMACSHA1]("HmacSHA1", 20)

sealed trait HMACSHA256

object HMACSHA256 extends WithMacSigningKey[HMACSHA256]("HmacSHA256", 32)

sealed trait HMACSHA384

object HMACSHA384 extends WithMacSigningKey[HMACSHA384]("HmacSHA384", 48)

sealed trait HMACSHA512

object HMACSHA512 extends WithMacSigningKey[HMACSHA512]("HmacSHA512", 64)
