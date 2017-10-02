package tsec.passwordhashers.imports

import cats.implicits._
import tsec.common.ErrorConstruct
import tsec.passwordhashers.core._

class PWHashInterpreter[T](implicit hasher: PasswordHasher[T]) extends PWHasherAlgebra[PasswordValidated, T] {

  def hashPassword(p: Password): T = hasher.hashPw(p)

  def hashPassUnsafe(p: Password, passwordOpt: Rounds): PasswordValidated[T] =
    Either.catchNonFatal(hasher.hashPw(p, passwordOpt)).leftMap(ErrorConstruct.fromThrowable[PasswordError])

  def checkPass(p: Password, hash: T): Boolean =
    hasher.checkPassword(p, hash)
}
