package fucc.all.encryption.passwordhashers.core

abstract class PWHashPrograms[F[_], A](algebra: DontHackMeBro[F, A], default: PasswordOpt)(implicit hasher: PasswordHasher[A]) {

  def hash(password: Password): F[A] = algebra.hashPass(password, default)

  def saltAndHash(salt: Salt, password: Password): F[A] = {
    algebra.hashPass(password,algebra.setSalt(salt))
  }

  def setRoundsAndHash(rounds: Rounds, password: Password): F[A] ={
    algebra.hashPass(password, algebra.setRounds(rounds))
  }

  def checkHashed(password: Password, hashed: A): F[Boolean] = algebra.checkPass(password, hashed)
}
