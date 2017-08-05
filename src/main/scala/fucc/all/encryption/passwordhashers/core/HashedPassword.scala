package fucc.all.encryption.passwordhashers.core

sealed trait HashedPassword
case class BCrypt(hashed: String) extends HashedPassword
case class PBKDF2(hashed: String) extends HashedPassword
case class SCrypt(hashed: String) extends HashedPassword
