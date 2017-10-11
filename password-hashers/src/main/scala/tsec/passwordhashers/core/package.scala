package tsec.passwordhashers

package object core {

  final case class Password(pass: String) extends AnyVal
  final case class Salt(salt: String)     extends AnyVal
  final case class Rounds(rounds: Int)    extends AnyVal

  final case class PasswordError(reason: String) extends Exception {
    override def getMessage: String = reason

    override def fillInStackTrace(): Throwable = this
  }

  type PasswordValidated[A] = Either[PasswordError, A]
  trait PasswordHasher[T] {
    protected val defaultRounds: Rounds
    def hashPw(pass: Password): T = hashPw(pass, defaultRounds)
    def hashPw(pass: Password, opt: Rounds): T
    def checkPassword(pass: Password, hashed: T): Boolean
  }
}
