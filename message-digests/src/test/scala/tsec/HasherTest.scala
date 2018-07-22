package tsec

import java.security.MessageDigest

import cats.effect.IO
import cats.Id
import fs2._
import org.scalatest.MustMatchers
import org.scalatest.prop.PropertyChecks
import tsec.common._
import tsec.hashing._
import tsec.hashing.jca._

class HasherTest extends TestSpec with MustMatchers with PropertyChecks {

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

  hashTests[MD5]
  hashTests[SHA1]
  hashTests[SHA256]
  hashTests[SHA512]
}
