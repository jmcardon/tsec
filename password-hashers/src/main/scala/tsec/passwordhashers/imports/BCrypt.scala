package tsec.passwordhashers.imports

import cats.syntax.either._
import tsec.passwordhashers.core._
import org.mindrot.jbcrypt.{BCrypt => JBCrypt}

final case class BCrypt(hashed: String)

object BCrypt {
  implicit lazy val BCryptHasher: PasswordHasher[BCrypt] =
    new PasswordHasher[BCrypt] {

      protected val defaultRounds: Rounds = Rounds(DefaultBcryptRounds)

      def hashPw(pass: Password, opt: Rounds): BCrypt =
        BCrypt(
          JBCrypt.hashpw(pass.pass, JBCrypt.gensalt(opt.rounds))
        )

      def checkPassword(pass: Password, hashed: BCrypt): Boolean =
        JBCrypt.checkpw(pass.pass, hashed.hashed)
    }

  object BCryptAlgebra extends PWHashInterpreter[BCrypt]

  implicit object BCryptPasswordHasher
      extends PWHashPrograms[PasswordValidated, BCrypt](BCryptAlgebra, Rounds(DefaultBcryptRounds))(
        BCrypt.BCryptHasher
      )
}
