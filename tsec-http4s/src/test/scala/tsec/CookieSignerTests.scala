package tsec

import java.util.UUID

import org.scalacheck.{Arbitrary, Gen}
import org.scalatest.MustMatchers
import org.scalatest.prop.PropertyChecks
import tsec.cookies.{CookieSigner, SignedCookie}
import tsec.mac.core.MacTag
import tsec.mac.imports._

class CookieSignerTests extends TestSpec with MustMatchers with PropertyChecks {

  implicit val arbitraryUUID: Arbitrary[UUID] = Arbitrary.apply(Gen.uuid)

  def signerTests[A](implicit tag: MacTag[A], keyGen: MacKeyGenerator[A]) = {
    behavior of "CookieSigner for algo " + tag.algorithm

    it should "Sign and verify any cookie properly with coercion" in {
      forAll { (s: String) =>
        val verified = for {
          key    <- keyGen.generateKey()
          signed <- CookieSigner.sign[A](s, System.currentTimeMillis().toString, key)
          stringer  = SignedCookie.toString[A](signed)
          recoerced = SignedCookie[A](stringer)
          verify <- CookieSigner.verify[A](recoerced, key)
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
          key    <- keyGen.generateKey()
          signed <- CookieSigner.sign[A](s, System.currentTimeMillis().toString, key)
          stringer  = SignedCookie.toString[A](signed)
          recoerced = SignedCookie[A](stringer)
          verify <- CookieSigner.verifyAndRetrieve[A](recoerced, key)
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
          key    <- keyGen.generateKey()
          key2   <- keyGen.generateKey()
          signed <- CookieSigner.sign[A](s, System.currentTimeMillis().toString, key)
          verify <- CookieSigner.verify[A](signed, key2)
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
          key    <- keyGen.generateKey()
          signed <- CookieSigner.sign[A](s.toString, System.currentTimeMillis().toString, key)
          stringer  = SignedCookie.toString[A](signed)
          recoerced = SignedCookie[A](stringer)
          verify <- CookieSigner.verifyAndRetrieve[A](recoerced, key)
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
