package fucc.all.encryption.passwordhashers.core

import fucc.all.encryption.passwordhashers.defaults.{DEFAULT_SCRYPT_N, DefaultScryptHasher}

class SCryptPasswordHasher(algebra: ImplAlgebra[SCrypt], default: PasswordOpt)(
    implicit hasher: PasswordHasher[SCrypt])
    extends PWHashPrograms[PasswordValidated, SCrypt](algebra, default)(hasher)

object SCryptPasswordHasher {
  def apply(hasher: PasswordHasher[SCrypt]): SCryptPasswordHasher =
    new SCryptPasswordHasher(new ImplAlgebra, Right(Rounds(DEFAULT_SCRYPT_N)))(hasher)
  implicit lazy val DefaultSC: SCryptPasswordHasher = apply(DefaultScryptHasher)
}
