package fucc.all.encryption.passwordhashers.core

trait DontHackMeBro[F[_], A] {

  def hashPass(p: Password, passwordOpt: PasswordOpt): F[A]

  def setSalt(salt: Salt): PasswordOpt

  def setRounds(rounds: Rounds): PasswordOpt

  def checkPass(p: Password, hash: A): F[Boolean]
}
