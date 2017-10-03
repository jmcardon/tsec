package tsec.passwordhashers

import cats.evidence.Is
import tsec.passwordhashers.core._
import org.mindrot.jbcrypt.{BCrypt => JBCrypt}
import com.lambdaworks.crypto.{SCryptUtil => JSCrypt}
import tsec.common.{IsString, StringEV}

package object imports {

  /**
    * https://security.stackexchange.com/questions/17207/recommended-of-rounds-for-bcrypt
    * Default is 10 on most applications
    */
  val DefaultBcryptRounds = 10

  /**
    * https://crypto.stackexchange.com/questions/35423/appropriate-scrypt-parameters-when-generating-an-scrypt-hash
    */
  val DefaultSCryptN = 14
  val DefaultSCryptR = 8
  val DefaultSCryptP = 1

  /**
    * http://www.tarsnap.com/scrypt/scrypt-slides.pdf
    */
  val SCryptHardenedN = 18
  val SCryptHardnedR  = 8
  val SCryptHardenedP = 2

  protected val BCrypt$$ : IsString = new IsString {
    type I = String
    val is = Is.refl[String]
  }

  type BCrypt = BCrypt$$.I

  implicit object BCrypt extends PasswordHasher[BCrypt] with StringEV[BCrypt] {
    @inline def from(a: String): BCrypt = BCrypt$$.is.flip.coerce(a)

    @inline def to(a: BCrypt): String = BCrypt$$.is.coerce(a)

    protected val defaultRounds: Rounds = Rounds(DefaultBcryptRounds)

    def hashPw(pass: Password, opt: Rounds): BCrypt =
      BCrypt$$.is.flip.coerce(JBCrypt.hashpw(pass.pass, JBCrypt.gensalt(opt.rounds)))

    def checkPassword(pass: Password, hashed: BCrypt): Boolean =
      JBCrypt.checkpw(pass.pass, hashed)
  }

  private object BCryptAlgebra extends PWHashInterpreter[BCrypt]

  implicit object BCryptPasswordHasher
      extends PWHashPrograms[PasswordValidated, BCrypt](BCryptAlgebra, Rounds(DefaultBcryptRounds))(BCrypt)

  protected val SCrypt$$ : IsString = new IsString {
    type I = String
    val is = Is.refl[String]
  }

  type SCrypt = SCrypt$$.I

  implicit object SCrypt extends PasswordHasher[SCrypt] with StringEV[SCrypt] {
    @inline def from(a: String): SCrypt = SCrypt$$.is.flip.coerce(a)

    @inline def to(a: SCrypt): String = SCrypt$$.is.coerce(a)

    protected val defaultRounds: Rounds = Rounds(DefaultSCryptR)

    def hashPw(pass: Password, opt: Rounds): SCrypt =
      SCrypt$$.is.flip
        .coerce(SCryptUtil.scrypt(pass.pass, math.pow(2, opt.rounds).toInt, DefaultSCryptR, DefaultSCryptP))

    def checkPassword(pass: Password, hashed: SCrypt): Boolean =
      JSCrypt.check(pass.pass, hashed)
  }

  implicit object SCryptAlgebra extends PWHashInterpreter[SCrypt]

  implicit object SCryptPasswordHasher
      extends PWHashPrograms[PasswordValidated, SCrypt](SCryptAlgebra, Rounds(DefaultSCryptN))(SCrypt)

  val HardenedSCrypt$$ : IsString = new IsString {
    type I = String
    val is = Is.refl[String]
  }

  type HardenedSCrypt = HardenedSCrypt$$.I

  implicit object HardenedSCrypt extends PasswordHasher[HardenedSCrypt] with StringEV[HardenedSCrypt] {

    @inline def from(a: String): HardenedSCrypt = HardenedSCrypt$$.is.flip.coerce(a)

    @inline def to(a: HardenedSCrypt): String = HardenedSCrypt$$.is.coerce(a)

    protected val defaultRounds: Rounds = Rounds(SCryptHardnedR)

    def hashPw(pass: Password, opt: Rounds): HardenedSCrypt =
      HardenedSCrypt$$.is.flip
        .coerce(SCryptUtil.scrypt(pass.pass, math.pow(2, opt.rounds).toInt, SCryptHardnedR, SCryptHardenedP))

    def checkPassword(pass: Password, hashed: HardenedSCrypt): Boolean =
      SCryptUtil.check(pass.pass, hashed)
  }

  object Hardened extends PWHashInterpreter[HardenedSCrypt]

  implicit object HardenedSCryptHasher
      extends PWHashPrograms[PasswordValidated, HardenedSCrypt](Hardened, Rounds(SCryptHardenedN))(HardenedSCrypt)

}
