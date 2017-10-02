package tsec.passwordhashers.core

abstract class PWHashPrograms[F[_], A](algebra: PWHasherAlgebra[F, A], val default: Rounds)(
    implicit hasher: PasswordHasher[A]
) {

  def hash(password: String): A = algebra.hashPassword(Password(password))

  def hassPassUnsafe(password: String, rounds: Rounds): F[A] =
    algebra.hashPassUnsafe(Password(password), rounds)

  def checkHashed(password: String, hashed: A): Boolean = algebra.checkPass(Password(password), hashed)
}
