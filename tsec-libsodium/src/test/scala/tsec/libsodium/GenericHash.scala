package tsec.libsodium

import java.security.MessageDigest

import cats.effect.IO
import fs2._
import tsec.common._
import tsec.hashing.CryptoHasher
import tsec.hashing.libsodium._
import tsec.hashing.libsodium.internal.SodiumHashPlatform

class GenericHash extends SodiumSpec {

  def hashTest[A](platform: SodiumHashPlatform[A])(
      implicit hasher: CryptoHasher[IO, A]
  ) = {
    behavior of "Sodium hash for " + platform.algorithm

    it should "hash two byte arrays into equal hash values" in {
      forAll { (s: String) =>
        val program = for {
          h1 <- platform.hash[IO](s.utf8Bytes)
          h2 <- platform.hash[IO](s.utf8Bytes)
        } yield (h1, h2)

        val (h1, h2) = program.unsafeRunSync()
        h1.toHexString mustBe h2.toHexString
      }
    }

    it should "work equally for streaming as for single chunk" in {
      forAll { (s: String) =>
        val program = for {
          h1 <- platform.hash[IO](s.utf8Bytes)
          h2 <- Stream.emits(s.utf8Bytes).covary[IO].through(platform.hashPipe).compile.toVector
        } yield (h1, h2.toArray)

        val (h1, h2) = program.unsafeRunSync()
        h1.toHexString mustBe h2.toHexString
      }
    }
  }

  hashTest(Blake2b)
  hashTest(SodiumSHA256)
  hashTest(SodiumSHA512)

  behavior of "Blake2b-specific functions"

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
      } yield MessageDigest.isEqual(h1, h2)

      program.unsafeRunSync() mustBe false
    }
  }

}
