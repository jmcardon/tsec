package tsec.passwordhashers.instances

import cats.implicits._
import tsec.passwordhashers.core._

class ImplAlgebra[T](implicit hasher: PasswordHasher[T]) extends PWHasherAlgebra[PasswordValidated, T] {
  def hashPass(p: Password, passwordOpt: Rounds): PasswordValidated[T] =
    Either.catchNonFatal(hasher.hashPw(p, passwordOpt)).leftMap(mapErr)

  def checkPass(p: Password, hash: T): PasswordValidated[Boolean] =
    Either.catchNonFatal(hasher.checkPassword(p, hash)).leftMap(mapErr)
}
