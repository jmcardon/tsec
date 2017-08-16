package tsec.passwordhashers

package object core {

  final case class Password(pass: String)        extends AnyVal
  final case class Salt(salt: String)            extends AnyVal
  final case class Rounds(rounds: Int)           extends AnyVal
  final case class PasswordError(reason: String) extends AnyVal

  type PasswordValidated[A] = Either[PasswordError, A]
  trait PasswordHasher[T] {
    def hashPw(pass: Password, opt: Rounds): T
    def checkPassword(pass: Password, hashed: T): Boolean
  }

  def mapErr(err: Throwable): PasswordError = PasswordError(err.getMessage)
}
