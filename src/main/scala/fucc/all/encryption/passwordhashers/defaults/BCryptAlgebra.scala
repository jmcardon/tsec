package fucc.all.encryption.passwordhashers.defaults

import fucc.all.encryption.passwordhashers.core._
import cats.implicits._

class BCryptAlgebra(implicit hasher: PasswordHasher[BCrypt]) extends DontHackMeBro[PasswordValidated, BCrypt] {
  def hashPass(p: Password, passwordOpt: PasswordOpt = Rounds(DEFAULT_BCRYPT_ROUNDS).asRight[Salt]): PasswordValidated[BCrypt] = {
    Either.catchNonFatal(hasher.hashPw(p, passwordOpt)).leftMap(mapErr)
  }

  def setSalt(salt: Salt): PasswordOpt = Left(salt)

  def setRounds(rounds: Rounds): PasswordOpt = Right(rounds)

  def checkPass(p: Password, hash: BCrypt): PasswordValidated[Boolean] = {
    Either.catchNonFatal(hasher.checkPassword(p, hash)).leftMap(mapErr)
  }
}
