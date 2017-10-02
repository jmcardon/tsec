package tsec.passwordhashers.core

trait PWHasherAlgebra[F[_], A] {

  def hashPassUnsafe(p: Password, passwordOpt: Rounds): F[A]

  def hashPassword(p: Password): A

  def checkPass(p: Password, hash: A): Boolean
}
