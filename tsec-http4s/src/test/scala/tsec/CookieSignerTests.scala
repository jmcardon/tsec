package tsec

import java.util.UUID

import org.scalacheck.{Arbitrary, Gen}
import tsec.cookies.CookieSigner
import tsec.mac.jca._
import cats.instances.either._
import cats.syntax.either._
import tsec.mac.MessageAuth

class CookieSignerTests extends TestSpec {

  implicit val arbitraryUUID: Arbitrary[UUID] = Arbitrary.apply(Gen.uuid)

  def signerTests[A](implicit M: MessageAuth[MacErrorM, A, MacSigningKey], keyGen: MacKeyGen[MacErrorM, A]) = {
    behavior of "CookieSigner for algo " + M.algorithm

    it should "Sign and verify any cookie properly with coercion" in {
      forAll { (s: String) =>
        val verified = for {
          key    <- keyGen.generateKey
          signed <- CookieSigner.sign(s, System.currentTimeMillis().toString, key)
          verify <- CookieSigner.verify(signed, key)
        } yield verify

        if (s.isEmpty)
          verified mustBe Left(MacSigningError("Cannot sign an empty string"))
        else
          verified mustBe Right(true)
      }
    }

    it should "Sign and retrieve properly for any properly signed message" in {
      forAll { (s: String) =>
        val verified = for {
          key    <- keyGen.generateKey
          signed <- CookieSigner.sign(s, System.currentTimeMillis().toString, key)
          verify <- CookieSigner.verifyAndRetrieve(signed, key)
        } yield verify

        if (s.isEmpty)
          verified mustBe Left(MacSigningError("Cannot sign an empty string"))
        else
          verified mustBe Right(s)
      }
    }

    it should "Not return true for verifying an incorrect key" in {
      forAll { (s: String) =>
        val verified = for {
          key    <- keyGen.generateKey
          key2   <- keyGen.generateKey
          signed <- CookieSigner.sign(s, System.currentTimeMillis().toString, key)
          verify <- CookieSigner.verify(signed, key2)
        } yield verify

        if (s.isEmpty)
          verified mustBe Left(MacSigningError("Cannot sign an empty string"))
        else
          verified mustBe Right(false)
      }
    }

    it should "verify UUIDs properly" in {
      forAll { (s: UUID) =>
        val verified = for {
          key    <- keyGen.generateKey
          signed <- CookieSigner.sign(s.toString, System.currentTimeMillis().toString, key)
          verify <- CookieSigner.verifyAndRetrieve(signed, key)
        } yield UUID.fromString(verify)
        verified mustBe Right(s)
      }
    }
  }

  signerTests[HMACSHA1]
  signerTests[HMACSHA256]
  signerTests[HMACSHA384]
  signerTests[HMACSHA512]

}
