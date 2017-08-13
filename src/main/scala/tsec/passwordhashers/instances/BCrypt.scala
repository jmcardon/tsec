package tsec.passwordhashers.instances

import cats.syntax.either._
import tsec.passwordhashers.core._
import org.mindrot.jbcrypt.{BCrypt => JBCrypt}

final case class BCrypt(hashed: String)

object BCrypt {
  implicit lazy val BCryptHasher: PasswordHasher[BCrypt] =
    new PasswordHasher[BCrypt] {
      def hashPw(pass: Password, opt: PasswordOpt): BCrypt =
        BCrypt(opt match {
          case Left(salt) => JBCrypt.hashpw(pass.pass, salt.salt)
          case Right(rounds) =>
            JBCrypt.hashpw(pass.pass, JBCrypt.gensalt(rounds.rounds))
        })

      def checkPassword(pass: Password, hashed: BCrypt): Boolean =
        JBCrypt.checkpw(pass.pass, hashed.hashed)
    }
}

object BCryptAlgebra extends ImplAlgebra[BCrypt]

class BCryptPasswordHasher(default: PasswordOpt)
    extends PWHashPrograms[PasswordValidated, BCrypt](BCryptAlgebra, default)(BCrypt.BCryptHasher)

object BCryptPasswordHasher {
  def apply(defaultOpt: PasswordOpt = Rounds(DefaultBcryptRounds).asRight[Salt]): BCryptPasswordHasher =
    new BCryptPasswordHasher(defaultOpt)
}
