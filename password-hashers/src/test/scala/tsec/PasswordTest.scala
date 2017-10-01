package tsec

import cats.Eq
import tsec.passwordhashers.core._
import tsec.passwordhashers.syntax._
import tsec.passwordhashers.instances._
import cats.syntax.either._

class PasswordTest extends TestSpec {

  implicit val PasswordErrorCatsEqInstance = new Eq[PasswordError] {
    override def eqv(x: PasswordError, y: PasswordError): Boolean =
      x.reason === y.reason
  }
  implicit val BCryptCatsEqInstance = new Eq[BCrypt] {
    override def eqv(x: BCrypt, y: BCrypt): Boolean = {
      x.hashed === y.hashed
    }
  }

  val plainPassword = "abc"

  /**
   * Our password spec in general
   * @param specname the name for ourspec
   * @param programs our password hasher programs to test against
   * @tparam A the password hashing algorithm
   */
  def testSpec[A: PasswordHasher](specname: String)(implicit programs:  PWHashPrograms[PasswordValidated, A]): Unit = {
    specname should "generate and verify with default settings" in {
      val hash: PasswordValidated[A] = plainPassword.hashPassword[A]

      assert(hash.flatMap(programs.checkHashed(plainPassword, _)) match {
        case Right(true) => true
        case _           => false
      })
    }

    it should "return different results for different rounds" in {
      assert(programs.setRoundsAndHash(plainPassword, Rounds(programs.default.rounds + 1)) !== programs.hash(plainPassword))
    }
  }

  testSpec[SCrypt]("SCrypt")

  testSpec[BCrypt]("BCrypt")

//  testSpec[HardenedSCrypt]("HardenedSCrypt")
}