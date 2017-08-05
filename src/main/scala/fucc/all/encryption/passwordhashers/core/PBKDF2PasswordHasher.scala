package fucc.all.encryption.passwordhashers.core

class PBKDF2PasswordHasher(algebra: ImplAlgebra[PBKDF2], default: PasswordOpt)(
  implicit hasher: PasswordHasher[PBKDF2])
  extends PWHashPrograms[PasswordValidated, PBKDF2](algebra, default)(hasher)
