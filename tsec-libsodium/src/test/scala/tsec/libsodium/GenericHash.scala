package tsec.libsodium

import cats.effect.IO
import tsec.common._
import tsec.libsodium.hashing._

class GenericHash extends SodiumSpec {

  behavior of "Generic Hashing spec"

  it should "hash two bytes to equal hashes" in {
    forAll { (s: String) =>
      val program = for {
        h1 <- Blake2b.hash[IO](s.utf8Bytes)
        h2 <- Blake2b.hash[IO](s.utf8Bytes)
      } yield (h1, h2)

      val (h1, h2) = program.unsafeRunSync()
      h1.toHexString mustBe h2.toHexString
    }
  }

  it should "not collide two different strings" in {
    forAll { (s1: String, s2: String) =>
      val program = for {
        h1 <- Blake2b.hash[IO](s1.utf8Bytes)
        h2 <- Blake2b.hash[IO](s2.utf8Bytes)
      } yield h1.toHexString == h2.toHexString

      program.unsafeRunSync() mustBe s1 == s2
    }
  }

  it should "hash properly for a particular key" in {
    forAll { (s: String) =>
      val program = for {
        k  <- Blake2b.generateKey[IO]
        h1 <- Blake2b.hashKeyed[IO](s.utf8Bytes, k)
        h2 <- Blake2b.hashKeyed[IO](s.utf8Bytes, k)
      } yield (h1, h2)

      val (h1, h2) = program.unsafeRunSync()
      h1.toHexString mustBe h2.toHexString
    }
  }

  it should "not authenticate for an incorrect key" in {
    forAll { (s: String) =>
      val program = for {
        k1 <- Blake2b.generateKey[IO]
        k2 <- Blake2b.generateKey[IO]
        h1 <- Blake2b.hashKeyed[IO](s.utf8Bytes, k1)
        h2 <- Blake2b.hashKeyed[IO](s.utf8Bytes, k2)
      } yield ByteUtils.constantTimeEquals(h1, h2)

      program.unsafeRunSync() mustBe false
    }
  }

}
