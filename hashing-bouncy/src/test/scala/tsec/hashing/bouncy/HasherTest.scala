package tsec.hashing.bouncy

import java.security.MessageDigest

import cats.Id
import cats.effect.IO
import fs2._
import tsec.TestSpec
import tsec.common._
import tsec.hashing.{CryptoHashAPI, CryptoHasher}

class HasherTest extends TestSpec {
  val str     = "hello World"
  val strList = List("a", "a", "bcd")

  def hashTests[A](implicit P1: CryptoHasher[Id, A], P2: CryptoHasher[IO, A]): Unit = {
    s"A cryptographic hash function for ${P1.algorithm}" should s"generate an equal hash for two equal byte arrays" in {
      forAll { (s1: String, s2: String) =>
        val h1 = P1.hash(s1.utf8Bytes)
        val h2 = P1.hash(s2.utf8Bytes)

        MessageDigest.isEqual(h1, h2) mustBe s1 == s2

      }
    }

    it should "generate an equal hash for piped byte arrays" in {
      forAll { (s1: String, s2: String) =>
        val h1 = Stream.emits(s1.utf8Bytes).covary[IO].through(P2.hashPipe)
        val h2 = Stream.emits(s2.utf8Bytes).covary[IO].through(P2.hashPipe)

        h1.compile.toList.unsafeRunSync() == h2.compile.toList.unsafeRunSync() mustBe s1 == s2
      }
    }

  }

  hashTests[Keccak224]
  hashTests[Keccak256]
  hashTests[Keccak384]
  hashTests[Keccak512]
  hashTests[Whirlpool]
  hashTests[RipeMD128]
  hashTests[RipeMD160]
  hashTests[RipeMD256]
  hashTests[RipeMD320]
  hashTests[Streebog256]
  hashTests[Streebog512]
  hashTests[Blake2B160]
  hashTests[Blake2B256]
  hashTests[Blake2B384]
  hashTests[Blake2B512]

}
