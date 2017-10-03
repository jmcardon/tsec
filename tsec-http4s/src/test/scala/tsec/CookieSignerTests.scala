package tsec

import tsec.common._
import org.scalatest.MustMatchers
import org.scalatest.prop.{Checkers, PropertyChecks}
import tsec.cookies.{CookieSigner, SignedCookie}
import tsec.mac.imports._

class CookieSignerTests extends TestSpec with MustMatchers with PropertyChecks {

  def signerTests[A : ByteEV](implicit tag: MacTag[A], keyGen: MacKeyGenerator[A]) = {
    behavior of "CookieSigner for algo " + tag.algorithm

    it should "Sign and verify any cookie properly" in {
      forAll { (s: String) =>
        val verified = for {
          key <- keyGen.generateKey()
          signed <- CookieSigner.sign[A](s, System.currentTimeMillis().toString, key)
          verify <- CookieSigner.verify[A](signed, key)
        } yield verify

        if(s.isEmpty)
          verified mustBe Left(MacSigningError("Cannot sign an empty string"))
        else
          verified mustBe Right(true)
      }
    }

    it should "Not return true for verifying an incorrect key" in {
      forAll { (s: String) =>
        val verified = for {
          key <- keyGen.generateKey()
          key2 <- keyGen.generateKey()
          signed <- CookieSigner.sign[A](s, System.currentTimeMillis().toString, key)
          verify <- CookieSigner.verify[A](signed, key2)
        } yield verify

        if(s.isEmpty)
          verified mustBe Left(MacSigningError("Cannot sign an empty string"))
        else
          verified mustBe Right(false)
      }
    }

    it should "coerce from string and back properly" in {
      forAll { (s: String) =>
        val verified = for {
          key <- keyGen.generateKey()
          signed <- CookieSigner.sign[A](s, System.currentTimeMillis().toString, key)
          stringer = SignedCookie.to[A](signed)
          recoerced = SignedCookie.fromRaw[A](stringer)
          verify <- CookieSigner.verify[A](recoerced, key)
        } yield verify

        if(s.isEmpty)
          verified mustBe Left(MacSigningError("Cannot sign an empty string"))
        else
          verified mustBe Right(true)
      }
    }
  }

  signerTests[HMACSHA1]
  signerTests[HMACSHA256]
  signerTests[HMACSHA384]
  signerTests[HMACSHA512]

}
