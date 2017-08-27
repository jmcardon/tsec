package tsec.passwordhashers.core

trait PWHasherAlgebra[F[_], A] {

  def hashPass(p: Password, passwordOpt: Rounds): F[A]

  def checkPass(p: Password, hash: A): F[Boolean]
}
