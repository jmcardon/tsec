package fucc.all.encryption.passwordhashers

import fucc.all.encryption.passwordhashers.core._
import org.mindrot.jbcrypt.{BCrypt => JBCrypt}
import com.lambdaworks.crypto.{SCryptUtil => JSCrypt}

package object defaults {
  /**
   * https://security.stackexchange.com/questions/17207/recommended-of-rounds-for-bcrypt
   * Default is 10 on most applications
   */
  val DEFAULT_BCRYPT_ROUNDS = 10


  /**
   * http://www.tarsnap.com/scrypt/scrypt-slides.pdf
   * https://crypto.stackexchange.com/questions/35423/appropriate-scrypt-parameters-when-generating-an-scrypt-hash
   */
  val DEFAULT_SCRYPT_P = 2
  val DEFAULT_SCRYPT_N = 16384
  val DEFAULT_SCRYPT_R = 8



  implicit lazy val DefaultBCryptHasher: PasswordHasher[BCrypt] = new PasswordHasher[BCrypt] {
    def hashPw(pass: Password, opt: PasswordOpt): BCrypt =
      BCrypt(opt match {
        case Left(salt) => JBCrypt.hashpw(pass.pass, salt.salt)
        case Right(rounds) => JBCrypt.hashpw(pass.pass, JBCrypt.gensalt(rounds.rounds))
      })

      def checkPassword(pass: Password, hashed: BCrypt): Boolean = {
        JBCrypt.checkpw(pass.pass, hashed.hashed)
      }
    }

  implicit lazy val DefaultScryptHasher = new PasswordHasher[SCrypt] {
    def hashPw(pass: Password, opt: PasswordOpt): SCrypt = SCrypt(JSCrypt.scrypt(pass.pass,DEFAULT_SCRYPT_N, DEFAULT_SCRYPT_R,DEFAULT_SCRYPT_P))

    def checkPassword(pass: Password, hashed: SCrypt): Boolean = JSCrypt.check(pass.pass, hashed.hashed)
  }

}
