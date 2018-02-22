package tsec

import java.security.MessageDigest

import cats.Eq
import cats.effect.IO
import org.scalatest.MustMatchers
import org.scalatest.prop.PropertyChecks
import tsec.common._
import tsec.passwordhashers.core._
import tsec.passwordhashers.imports._

class PasswordTest extends TestSpec with MustMatchers with PropertyChecks {

  implicit val PasswordErrorCatsEqInstance = new Eq[PasswordError] {
    override def eqv(x: PasswordError, y: PasswordError): Boolean =
      x.cause === y.cause
  }
  implicit val BCryptCatsEqInstance = new Eq[BCrypt] {
    override def eqv(x: BCrypt, y: BCrypt): Boolean =
      x === y
  }

  val plainPassword = "abc213A"

  /** Our password spec in general
    * @param specname the name for our spec
    * @param programs our password hasher programs to test against
    * @tparam A the password hashing algorithm
    */
  final def testSpec[A](specname: String)(programs: PasswordHasher[A, DummyImplicit]): Unit = {
    specname should "generate and verify with default settings" in {
      forAll { (s: String) =>
        val hash =
          for {
            pass  <- programs.hashpw[IO](s)
            check <- programs.checkpw[IO](s, pass)
          } yield check

        hash.unsafeRunSync() mustBe true
      }
    }

    specname should "generate and verify with default settings for chars" in {
      forAll { (s: String) =>
        val arr      = s.toCharArray
        val checkArr = s.toCharArray
        val hash =
          for {
            pass  <- programs.hashpw[IO](arr)
            check <- programs.checkpw[IO](checkArr, pass)
          } yield check

        hash.unsafeRunSync() mustBe true
        new String(arr) mustBe new String(Array.fill[Char](arr.length)(0.toChar))
        new String(checkArr) mustBe new String(Array.fill[Char](arr.length)(0.toChar))
      }
    }

    specname should "generate and verify with default settings for bytes" in {
      forAll { (s: String) =>
        val arr      = s.utf8Bytes
        val checkArr = s.utf8Bytes
        val hash =
          for {
            pass  <- programs.hashpw[IO](arr)
            check <- programs.checkpw[IO](checkArr, pass)
          } yield check

        hash.unsafeRunSync() mustBe true
        val zeroArray = Array.fill[Byte](arr.length)(0)
        MessageDigest.isEqual(arr, zeroArray) mustBe true
        MessageDigest.isEqual(checkArr, zeroArray) mustBe true

      }
    }

    it should "not verify for an incorrect password" in {
      forAll { (s1: String, s2: String) =>
        val hash =
          for {
            pass  <- programs.hashpw[IO](s1)
            check <- programs.checkpw[IO](s2, pass)
          } yield check

        hash.unsafeRunSync() mustBe s1 == s2
      }
    }
  }

  testSpec[SCrypt]("SCrypt")(SCrypt)

  testSpec[BCrypt]("BCrypt")(BCrypt)

//  testSpec[HardenedSCrypt]("HardenedSCrypt") //Note: Takes _forever_

  behavior of "BCrypt only variable rounds"

  it should "hash properly for more than 10 rounds" in {
    val dummy = "hihi"
    val hash = for {
      pass  <- BCrypt.hashpwWithRounds[IO](dummy, 11)
      check <- BCrypt.checkpw[IO](dummy, pass)
    } yield check

    hash.unsafeRunSync() mustBe true
  }

}
