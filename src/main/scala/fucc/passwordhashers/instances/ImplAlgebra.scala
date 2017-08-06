package fucc.passwordhashers.instances

import cats.implicits._
import fucc.passwordhashers.core._

class ImplAlgebra[T](implicit hasher: PasswordHasher[T]) extends PWHasherAlgebra[PasswordValidated, T] {
  def hashPass(p: Password, passwordOpt: PasswordOpt): PasswordValidated[T] = {
    Either.catchNonFatal(hasher.hashPw(p, passwordOpt)).leftMap(mapErr)
  }

  def setSalt(salt: Salt): PasswordOpt = Left(salt)

  def setRounds(rounds: Rounds): PasswordOpt = Right(rounds)

  def checkPass(p: Password, hash: T): PasswordValidated[Boolean] = {
    Either.catchNonFatal(hasher.checkPassword(p, hash)).leftMap(mapErr)
  }
}
