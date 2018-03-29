package tsec.libsodium

import cats.effect.IO
import org.scalacheck.{Arbitrary, Gen}
import tsec.passwordhashers._
import tsec.passwordhashers.libsodium._
import tsec.passwordhashers.libsodium.internal.SodiumPasswordHasher

class SodiumPWHashTest extends SodiumSpec {

  implicit val genStringAscii: Gen[String] = {
    val choose = Gen.choose(33.toChar, 126.toChar)
    Gen.listOf(choose).map(_.mkString)
  }
  implicit val arbStr = Arbitrary(genStringAscii)

  def testPasswordHash[P, S](hasher: SodiumPasswordHasher[P], stren: S)(
      implicit p: PWStrengthParam[P, S],
    P: PasswordHasher[IO, P]
  ) = {
    behavior of s"${hasher.hashingAlgorithm} with strength $stren"

    it should "hash and verify properly" in {
      forAll { (s: String) =>
        val program = for {
          hashed   <- hasher.hashpwWithStrength[IO, S](s, stren)
          verified <- hasher.checkpwBool[IO](s, hashed)
        } yield verified

        if (!s.isEmpty) {
          program.unsafeRunSync() mustBe true
        } else
          program.attempt.unsafeRunSync() mustBe a[Left[SodiumPasswordError, _]]
      }
    }

    it should "hash and verify properly (short circuit)" in {
      forAll { (s: String) =>
        val program = for {
          hashed <- hasher.hashpwWithStrength[IO, S](s, stren)
          _      <- hasher.checkPassShortCircuit[IO](s, hashed)
        } yield ()

        if (!s.isEmpty) {
          program.unsafeRunSync() mustBe (())
        } else
          program.attempt.unsafeRunSync() mustBe a[Left[SodiumPasswordError, _]]
      }
    }

    it should "not verify for an incorrect password" in {
      forAll { (s: String, s2: String) =>
        val program = for {
          hashed   <- hasher.hashpwWithStrength[IO, S](s, stren)
          verified <- hasher.checkpwBool[IO](s2, hashed)
        } yield verified
        if (!s.isEmpty)
          program.unsafeRunSync() mustBe s == s2
        else
          program.attempt.unsafeRunSync() mustBe a[Left[SodiumPasswordError, _]]
      }
    }

    it should "not verify for an incorrect password(short circuit)" in {
      forAll { (s: String, s2: String) =>
        val program = for {
          hashed   <- hasher.hashpwWithStrength[IO, S](s, stren)
          verified <- hasher.checkPassShortCircuit[IO](s2, hashed)
        } yield verified
        if (!s.isEmpty && s == s2)
          program.unsafeRunSync() mustBe (())
        else
          program.attempt.unsafeRunSync() mustBe a[Left[SodiumPasswordError, _]]
      }
    }

  }

  testPasswordHash(Argon2, PasswordStrength.MinStrength)
  testPasswordHash(Argon2, PasswordStrength.InteractiveStrength)
  testPasswordHash(Argon2, PasswordStrength.ModerateStrength)
//  testPasswordHash(Argon2, PasswordStrength.SensitiveStrength) //This takes _forever_

  testPasswordHash(SodiumSCrypt, PasswordStrength.MinStrength)
  testPasswordHash(SodiumSCrypt, PasswordStrength.InteractiveStrength)
//  testPasswordHash(SodiumSCrypt, PasswordStrength.SensitiveStrength) //This takes _forever_

}
