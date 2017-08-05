package fucc.all.encryption.passwordhashers.defaults

import fucc.all.encryption.passwordhashers.core._
import cats.syntax.either._

class BCryptPasswordHasher(algebra: BCryptAlgebra, default: PasswordOpt)(
    implicit hasher: PasswordHasher[BCrypt])
    extends PWHashPrograms[PasswordValidated, BCrypt](algebra, default)(hasher)

object BCryptPasswordHasher {
  def apply(hasher: PasswordHasher[BCrypt],
            defaultOpt: PasswordOpt = Rounds(DEFAULT_BCRYPT_ROUNDS)
              .asRight[Salt]): BCryptPasswordHasher =
    new BCryptPasswordHasher(new BCryptAlgebra, defaultOpt)(hasher)

  implicit lazy val Default: BCryptPasswordHasher = apply(DefaultBCrypt)
}
