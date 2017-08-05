package fucc.all.encryption.passwordhashers

import fucc.all.encryption.passwordhashers.core._
import org.mindrot.jbcrypt.{BCrypt => JBCrypt}

package object defaults {
  val DEFAULT_BCRYPT_ROUNDS = 10

  implicit lazy val DefaultBCrypt: PasswordHasher[BCrypt] = new PasswordHasher[BCrypt] {
    def hashPw(pass: Password, opt: PasswordOpt): BCrypt =
      BCrypt(opt match {
        case Left(salt) => JBCrypt.hashpw(pass.pass, salt.salt)
        case Right(rounds) => JBCrypt.hashpw(pass.pass, JBCrypt.gensalt(rounds.rounds))
      })

      def checkPassword(pass: Password, hashed: BCrypt): Boolean = {
        JBCrypt.checkpw(pass.pass, hashed.hashed)
      }
    }

}
