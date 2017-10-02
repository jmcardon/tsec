package tsec

import java.time.Instant

import org.scalatest.MustMatchers
import tsec.core.ByteUtils.ByteAux
import tsec.jws.JWSSerializer
import tsec.jws.mac._
import tsec.jwt.JWTClaims
import tsec.jwt.algorithms.JWTMacAlgo

import scala.concurrent.duration._
import tsec.mac.imports._

class JWTMacTests extends TestSpec with MustMatchers {

  def jwtBehavior[A: ByteAux](
    implicit algo: JWTMacAlgo[A],
    cv: JWSMacCV[MacErrorM, A],
    hs: JWSSerializer[JWSMacHeader[A]]
  ) {
    behavior of "JWT " + algo.jwtRepr

    it should "sign and verify properly with no expiry" in {
      val res = for {
        key      <- algo.keyGen.generateKey()
        jwt      <- JWTMac.build[A](JWTClaims(), key)
        verified <- JWTMac.verifyFromInstance[A](jwt, key)
      } yield verified

      res mustBe Right(true)
    }

    it should "sign and verify properly for proper expiry" in {
      val res = for {
        key      <- algo.keyGen.generateKey()
        jwt      <- JWTMac.build[A](JWTClaims().withExpiry(10.seconds), key)
        verified <- JWTMac.verifyFromInstance[A](jwt, key)
      } yield verified

      res mustBe Right(true)
    }

    it should "sign and verify properly for proper nbf, iat, and expiry" in {
      val res = for {
        key <- algo.keyGen.generateKey()
        jwt <- JWTMac.build[A](JWTClaims(notBefore = Some(Instant.now().minusSeconds(2).getEpochSecond)).withExpiry(10.seconds), key)
        verified <- JWTMac.verifyFromInstance[A](jwt, key)
      } yield verified

      res mustBe Right(true)
    }

    it should "fail verification for expired token" in {
      val expired = Instant.now().minusSeconds(20)

      val res = for {
        key      <- algo.keyGen.generateKey()
        jwt      <- JWTMac.build[A](JWTClaims(expiration = Some(expired.getEpochSecond)), key)
        verified <- JWTMac.verifyFromInstance[A](jwt, key)
      } yield verified
      res mustBe Right(false)
    }

    it should "fail verification if evaluated before nbf" in {
      val nbf = Instant.now().plusSeconds(20)
      val res = for {
        key      <- algo.keyGen.generateKey()
        jwt      <- JWTMac.build[A](JWTClaims(notBefore = Some(nbf.getEpochSecond)), key)
        verified <- JWTMac.verifyFromInstance[A](jwt, key)
      } yield verified
      res mustBe Right(false)
    }

    it should "fail verification if iat is some nonsensical time in the future" in {
      val res = for {
        key      <- algo.keyGen.generateKey()
        jwt      <- JWTMac.build[A](JWTClaims().withIAT(20.seconds), key)
        verified <- JWTMac.verifyFromInstance[A](jwt, key)
      } yield verified
      res mustBe Right(false)
    }
  }

  jwtBehavior[HMACSHA256]
  jwtBehavior[HMACSHA512]
  jwtBehavior[HMACSHA384]

  "JWTS" should "not properly deserialize a JWT that is signed with a different algorithm and key" in {
    val res = for {
      key <- HMACSHA256.keyGen.generateKey()
      key2 <- HMACSHA384.keyGen.generateKey()
      jwtString <- JWTMac.signToString[HMACSHA256](JWTClaims(), key)
      verif <- JWTMac.verifyFromString[HMACSHA384](jwtString, key2)
    } yield verif

    res mustBe Right(false)
  }

}