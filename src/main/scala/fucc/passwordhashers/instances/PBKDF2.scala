package fucc.passwordhashers.instances

case class PBKDF2(hashed: String)

import fucc.passwordhashers.core.{PWHashPrograms, PasswordHasher, PasswordOpt, PasswordValidated}

class PBKDF2PasswordHasher(algebra: ImplAlgebra[PBKDF2], default: PasswordOpt)(
  implicit hasher: PasswordHasher[PBKDF2])
  extends PWHashPrograms[PasswordValidated, PBKDF2](algebra, default)(hasher)
