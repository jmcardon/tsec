package tsec

import java.time.Instant

import cats.effect.IO
import org.scalatest.MustMatchers
import tsec.common._
import tsec.jws.JWSSerializer
import tsec.mac.imports._
import tsec.jws.mac._
import tsec.jwt.JWTClaims
import tsec.jwt.algorithms.JWTMacAlgo

import scala.concurrent.duration._

class JWTMacTests extends TestSpec with MustMatchers {

  def jwtBehavior[A](
      implicit algo: JWTMacAlgo[A],
      cv: JWSMacCV[MacErrorM, A],
      cv2: JWSMacCV[IO, A],
      hs: JWSSerializer[JWSMacHeader[A]],
      keyGen: MacKeyGenerator[A]
  ) {
    behavior of "JWT pure" + algo.jwtRepr

    it should "sign and verify properly with no expiry" in {
      val res = for {
        key      <- keyGen.generateLift[IO]
        jwt      <- JWTMac.build[IO, A](JWTClaims(), key)
        verified <- JWTMac.verifyFromInstance[IO, A](jwt, key)
      } yield verified

      res.unsafeRunSync() mustBe true
    }

    it should "sign and verify properly for proper expiry" in {
      val res = for {
        key      <- keyGen.generateLift[IO]
        jwt      <- JWTMac.build[IO, A](JWTClaims().withExpiry(10.seconds), key)
        verified <- JWTMac.verifyFromInstance[IO, A](jwt, key)
      } yield verified

      res.unsafeRunSync() mustBe true
    }

    it should "sign and verify properly for proper nbf, iat, and expiry" in {
      val res = for {
        key <- keyGen.generateLift[IO]
        jwt <- JWTMac.build[IO, A](
          JWTClaims(notBefore = Some(Instant.now().minusSeconds(2).getEpochSecond)).withExpiry(10.seconds),
          key
        )
        verified <- JWTMac.verifyFromInstance[IO, A](jwt, key)
      } yield verified

      res.unsafeRunSync() mustBe true
    }

    it should "fail verification for expired token" in {
      val expired = Instant.now().minusSeconds(20)

      val res = for {
        key      <- keyGen.generateLift[IO]
        jwt      <- JWTMac.build[IO, A](JWTClaims(expiration = Some(expired.getEpochSecond)), key)
        verified <- JWTMac.verifyFromInstance[IO, A](jwt, key)
      } yield verified
      res.unsafeRunSync() mustBe false
    }

    it should "fail verification if evaluated before nbf" in {
      val nbf = Instant.now().plusSeconds(20)
      val res = for {
        key      <- keyGen.generateLift[IO]
        jwt      <- JWTMac.build[IO, A](JWTClaims(notBefore = Some(nbf.getEpochSecond)), key)
        verified <- JWTMac.verifyFromInstance[IO, A](jwt, key)
      } yield verified
      res.unsafeRunSync() mustBe false
    }

    it should "fail verification if iat is some nonsensical time in the future" in {
      val res = for {
        key      <- keyGen.generateLift[IO]
        jwt      <- JWTMac.build[IO, A](JWTClaims().withIAT(20.seconds), key)
        verified <- JWTMac.verifyFromInstance[IO, A](jwt, key)
      } yield verified
      res.unsafeRunSync() mustBe false
    }

    behavior of "JWT impure" + algo.jwtRepr

    it should "sign and verify properly with no expiry" in {
      val res = for {
        key      <- keyGen.generateKey()
        jwt      <- JWTMacImpure.build[A](JWTClaims(), key)
        verified <- JWTMacImpure.verifyFromInstance[A](jwt, key)
      } yield verified

      res mustBe Right(true)
    }

    it should "sign and verify properly for proper expiry" in {
      val res = for {
        key      <- keyGen.generateKey()
        jwt      <- JWTMacImpure.build[A](JWTClaims().withExpiry(10.seconds), key)
        verified <- JWTMacImpure.verifyFromInstance[A](jwt, key)
      } yield verified

      res mustBe Right(true)
    }

    it should "sign and verify properly for proper nbf, iat, and expiry" in {
      val res = for {
        key <- keyGen.generateKey()
        jwt <- JWTMacImpure.build[A](
          JWTClaims(notBefore = Some(Instant.now().minusSeconds(2).getEpochSecond)).withExpiry(10.seconds),
          key
        )
        verified <- JWTMacImpure.verifyFromInstance[A](jwt, key)
      } yield verified

      res mustBe Right(true)
    }

    it should "fail verification for expired token" in {
      val expired = Instant.now().minusSeconds(20)

      val res = for {
        key      <- keyGen.generateKey()
        jwt      <- JWTMacImpure.build[A](JWTClaims(expiration = Some(expired.getEpochSecond)), key)
        verified <- JWTMacImpure.verifyFromInstance[A](jwt, key)
      } yield verified
      res mustBe Right(false)
    }

    it should "fail verification if evaluated before nbf" in {
      val nbf = Instant.now().plusSeconds(20)
      val res = for {
        key      <- keyGen.generateKey()
        jwt      <- JWTMacImpure.build[A](JWTClaims(notBefore = Some(nbf.getEpochSecond)), key)
        verified <- JWTMacImpure.verifyFromInstance[A](jwt, key)
      } yield verified
      res mustBe Right(false)
    }

    it should "fail verification if iat is some nonsensical time in the future" in {
      val res = for {
        key      <- keyGen.generateKey()
        jwt      <- JWTMacImpure.build[A](JWTClaims().withIAT(20.seconds), key)
        verified <- JWTMacImpure.verifyFromInstance[A](jwt, key)
      } yield verified
      res mustBe Right(false)
    }
  }

  jwtBehavior[HMACSHA256]
  jwtBehavior[HMACSHA512]
  jwtBehavior[HMACSHA384]

  "JWTS" should "not properly deserialize a JWT that is signed with a different algorithm and key" in {
    val res = for {
      key       <- HMACSHA256.keyGen.generateKey()
      key2      <- HMACSHA384.keyGen.generateKey()
      jwtString <- JWTMacImpure.buildToString[HMACSHA256](JWTClaims(), key)
      verif     <- JWTMacImpure.verifyFromString[HMACSHA384](jwtString, key2)
    } yield verif

    res mustBe Right(false)
  }

}
