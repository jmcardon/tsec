package tsec

import cats.Eq
import tsec.passwordhashers._
import tsec.passwordhashers.core._
import tsec.passwordhashers.imports._

class PasswordTest extends TestSpec {

  implicit val PasswordErrorCatsEqInstance = new Eq[PasswordError] {
    override def eqv(x: PasswordError, y: PasswordError): Boolean =
      x.reason === y.reason
  }
  implicit val BCryptCatsEqInstance = new Eq[BCrypt] {
    override def eqv(x: BCrypt, y: BCrypt): Boolean =
      x === y
  }

  val plainPassword = "abc"

  /** Our password spec in general
    * @param specname the name for ourspec
    * @param programs our password hasher programs to test against
    * @tparam A the password hashing algorithm
    */
  def testSpec[A: PasswordHasher](specname: String)(implicit programs: PWHashPrograms[PasswordValidated, A]): Unit = {
    specname should "generate and verify with default settings" in {
      val hash: A = plainPassword.hashPassword[A]

      assert(programs.checkHashed(plainPassword, hash))
    }

    it should "return different results for different rounds" in {
      assert(
        programs.hassPassUnsafe(plainPassword, Rounds(programs.default.rounds + 1)) !== Right(programs.hash(plainPassword))
      )
    }
  }

  testSpec[SCrypt]("SCrypt")

  testSpec[BCrypt]("BCrypt")

//  testSpec[HardenedSCrypt]("HardenedSCrypt")
}
