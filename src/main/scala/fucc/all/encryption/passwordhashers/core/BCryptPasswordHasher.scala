package fucc.all.encryption.passwordhashers.core

import cats.syntax.either._
import fucc.all.encryption.passwordhashers.defaults.{DEFAULT_BCRYPT_ROUNDS, DefaultBCryptHasher}

class BCryptPasswordHasher(algebra: ImplAlgebra[BCrypt], default: PasswordOpt)(
    implicit hasher: PasswordHasher[BCrypt])
    extends PWHashPrograms[PasswordValidated, BCrypt](algebra, default)(hasher)

object BCryptPasswordHasher {
  def apply(hasher: PasswordHasher[BCrypt],
            defaultOpt: PasswordOpt = Rounds(DEFAULT_BCRYPT_ROUNDS)
              .asRight[Salt]): BCryptPasswordHasher =
    new BCryptPasswordHasher(new ImplAlgebra, defaultOpt)(hasher)

  implicit lazy val DefaultBCrypt: BCryptPasswordHasher = apply(DefaultBCryptHasher)
}
