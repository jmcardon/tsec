package fucc.passwordhashers.instances

import fucc.passwordhashers.core._
import com.lambdaworks.crypto.{PBKDF => JPBK}


case class PBKDF2SHA1(hashed: String)

object PBKDF2SHA1 {
  implicit val hasher: PasswordHasher[PBKDF2SHA1] = ???
}



class PBKDF2PasswordHasher(algebra: ImplAlgebra[PBKDF2SHA1], default: PasswordOpt)(
  implicit hasher: PasswordHasher[PBKDF2SHA1])
  extends PWHashPrograms[PasswordValidated, PBKDF2SHA1](algebra, default)(hasher)
