package tsec.libsodium

import cats.effect.IO
import tsec.common._
import tsec.libsodium.authentication._
import tsec.libsodium.authentication.internal.SodiumMacPlatform

class SodiumMacTests extends SodiumSpec {

  final def macTest[A](platform: SodiumMacPlatform[A]) = {
    behavior of platform.algorithm

    it should "sign and verify for the same key" in {
      forAll { (s: String) =>
        val program = for {
          key      <- platform.generateKey[IO]
          signed   <- platform.sign[IO](s.utf8Bytes, key)
          verified <- platform.verify[IO](s.utf8Bytes, signed, key)
        } yield verified

        program.unsafeRunSync() mustBe true
      }
    }

    it should "not sign and verify for a different key but correct input" in {
      forAll { (s: String) =>
        val program = for {
          key1     <- platform.generateKey[IO]
          key2     <- platform.generateKey[IO]
          signed   <- platform.sign[IO](s.utf8Bytes, key1)
          verified <- platform.verify[IO](s.utf8Bytes, signed, key2)
        } yield verified

        program.unsafeRunSync() mustBe false
      }
    }

    it should "not sign and verify for the same key but incorrect input" in {
      forAll { (s: String, s2: String) =>
        val program = for {
          key      <- platform.generateKey[IO]
          signed   <- platform.sign[IO](s.utf8Bytes, key)
          verified <- platform.verify[IO](s2.utf8Bytes, signed, key)
        } yield verified

        program.unsafeRunSync() mustBe s == s2
      }
    }
  }

  macTest(HS256)
  macTest(HS512)

}
