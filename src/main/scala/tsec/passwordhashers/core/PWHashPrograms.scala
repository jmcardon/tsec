package tsec.passwordhashers.core

abstract class PWHashPrograms[F[_], A](algebra: PWHasherAlgebra[F, A], default: Rounds)(
    implicit hasher: PasswordHasher[A]
) {

  def hash(password: String): F[A] = algebra.hashPass(Password(password), default)

  def setRoundsAndHash(password: String, rounds: Rounds): F[A] =
    algebra.hashPass(Password(password), rounds)

  def checkHashed(password: String, hashed: A): F[Boolean] = algebra.checkPass(Password(password), hashed)
}
