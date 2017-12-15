package tsec.libsodium.authentication

import cats.effect.IO
import tsec.common._
import tsec.libsodium.SodiumSpec

class OnetimeAuthTest extends SodiumSpec {

  behavior of "One-Time authentication"

  it should "verify message properly" in {
    forAll { (s: String) =>
      val program: IO[Boolean] = for {
        key <- OnetimeAuth.generateKey[IO]
        message = s.utf8Bytes
        tag  <- OnetimeAuth.generateTag[IO](key, message)
        isOk <- OnetimeAuth.verify[IO](key, message, tag)
      } yield isOk

      program.unsafeRunSync() mustBe true
    }
  }

  it should "not verify manipulated message" in {
    forAll { (s1: String, s2: String) =>
      whenever(s1 != s2) {
        val program: IO[Boolean] = for {
          key <- OnetimeAuth.generateKey[IO]
          message = s1.utf8Bytes
          message2 = s2.utf8Bytes
          tag <- OnetimeAuth.generateTag[IO](key, message)
          isOk <- OnetimeAuth.verify[IO](key, message2, tag)
        } yield isOk

        program.unsafeRunSync() mustBe false
      }
    }
  }

}
