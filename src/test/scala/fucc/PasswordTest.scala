import cats.Eq
import fucc.messagedigests.javahasher._
import fucc.messagedigests.javahasher.syntax._
import fucc.passwordhashers.core._
import fucc.passwordhashers.syntax._
import fucc.passwordhashers.instances._
import cats.syntax.either._
import fucc.passwordhashers.instances.HardenedSCrypt.SCryptPasswordHasher
import fucc.passwordhashers.instances.SCrypt.SCryptPasswordHasher

class PasswordTest extends TestSpec {

  val plainPassword = "abc"

  /**
    * Bcrypt
    */

  "BCrypt password hasher" should "generate and verify with default settings" in {
    implicit val bcrypt = BCryptPasswordHasher()
    val hash: PasswordValidated[BCrypt] = plainPassword.hash

    assert(hash.flatMap(bcrypt.checkHashed(plainPassword, _)) match {
      case Right(true) => true
      case _           => false
    })
  }

  it should "syntax should generate same result" in {
    val bcrypt = BCryptPasswordHasher()
    val hash1: PasswordValidated[BCrypt] = bcrypt.hash(plainPassword)
    val hash2: PasswordValidated[BCrypt] = plainPassword.hash(bcrypt)

    assert(hash1 === hash2)
  }

  it should "return different results for different rounds" in {
    val bcrypt1 = BCryptPasswordHasher(Rounds(DefaultBcryptRounds).asRight[Salt])
    val bcrypt2 = BCryptPasswordHasher(Rounds(DefaultBcryptRounds+1).asRight[Salt])

    assert(bcrypt1.hash(plainPassword) !== bcrypt2.hash(plainPassword))
  }

}
