package fucc.passwordhashers.core

abstract class PWHashPrograms[F[_], A](algebra: PWHasherAlgebra[F, A], default: PasswordOpt)(implicit hasher: PasswordHasher[A]) {

  def hash(password: String): F[A] = algebra.hashPass(Password(password), default)

  def saltAndHash(password: String, salt: Salt): F[A] = {
    algebra.hashPass(Password(password),algebra.setSalt(salt))
  }

  def setRoundsAndHash(password: String, rounds: Rounds): F[A] ={
    algebra.hashPass(Password(password), algebra.setRounds(rounds))
  }

  def checkHashed(password: String, hashed: A): F[Boolean] = algebra.checkPass(Password(password), hashed)
}
