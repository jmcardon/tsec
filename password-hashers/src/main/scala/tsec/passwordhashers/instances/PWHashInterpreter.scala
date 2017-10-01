package tsec.passwordhashers.instances

import cats.implicits._
import tsec.core.ErrorConstruct
import tsec.passwordhashers.core._

class PWHashInterpreter[T](implicit hasher: PasswordHasher[T]) extends PWHasherAlgebra[PasswordValidated, T] {
  def hashPass(p: Password, passwordOpt: Rounds): PasswordValidated[T] =
    Either.catchNonFatal(hasher.hashPw(p, passwordOpt)).leftMap(ErrorConstruct.fromThrowable[PasswordError])

  def checkPass(p: Password, hash: T): PasswordValidated[Boolean] =
    Either.catchNonFatal(hasher.checkPassword(p, hash)).leftMap(ErrorConstruct.fromThrowable[PasswordError])
}
