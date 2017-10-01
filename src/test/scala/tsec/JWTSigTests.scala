package tsec

import java.security.Security

import cats.effect.IO

import tsec.jws.signature.{JWSSigCV, JWSSignedHeader, JWTSig, JWTSigSync}
import tsec.jwt.algorithms.JWTSigAlgo
import tsec.jwt.claims.JWTClaims
import tsec.signature.instance._

import scala.concurrent.duration._
import java.time.Instant
import org.bouncycastle.jce.provider.BouncyCastleProvider

import org.scalatest.MustMatchers



class JWTSigTests extends TestSpec with MustMatchers {

  if (Security.getProvider("BC") == null)
    Security.addProvider(new BouncyCastleProvider())

  val F = IO.ioEffect

  def jwtSigTest[A](implicit algoTag: JWTSigAlgo[A], kfTag: KFTag[A], cv: JWSSigCV[IO, A], cv2: JWSSigCV[SigErrorM, A]) = {
    behavior of s"JWT signature-style ${algoTag.jwtRepr} - pure"

    it should "Sign and verify properly for proper params" in {
      val expression: IO[JWTSig[A]] = for {
        keyPair <- F.fromEither(kfTag.generateKeyPair)
        build <- JWTSigSync.signToString[IO, A](
          JWSSignedHeader[A](),
          JWTClaims(issuedAt = Some(Instant.now.minusSeconds(2).getEpochSecond)).withExpiry(5.seconds),
          keyPair.privateKey
        )
        verified <- JWTSigSync.verifyK[IO, A](build, keyPair.publicKey)
      } yield verified

      expression.unsafeRunSync() mustBe a[JWTSig[_]]
    }

    it should "not verify for an incorrect key" in {
      val expression: IO[JWTSig[A]] = for {
        keyPair  <- F.fromEither(kfTag.generateKeyPair)
        keyPair2 <- F.fromEither(kfTag.generateKeyPair)
        build <- JWTSigSync.signToString[IO, A](
          JWSSignedHeader[A](),
          JWTClaims(issuedAt = Some(Instant.now.minusSeconds(2).getEpochSecond)).withExpiry(5.seconds),
          keyPair.privateKey
        )
        verified <- JWTSigSync.verifyK[IO, A](build, keyPair2.publicKey)
      } yield verified

      expression.attempt.unsafeRunSync() mustBe a[Left[Throwable, _]]
    }

    it should "not verify for an expired claim" in {
      val expression: IO[JWTSig[A]] = for {
        keyPair <- F.fromEither(kfTag.generateKeyPair)
        build <- JWTSigSync.signToString[IO, A](
          JWSSignedHeader[A](),
          JWTClaims(expiration = Some(Instant.now.minusSeconds(2).getEpochSecond)),
          keyPair.privateKey
        )
        verified <- JWTSigSync.verifyK[IO, A](build, keyPair.publicKey)
      } yield verified

      expression.attempt.unsafeRunSync() mustBe a[Left[Throwable, _]]
    }

    it should "not verify for a future iat" in {
      val expression: IO[JWTSig[A]] = for {
        keyPair <- F.fromEither(kfTag.generateKeyPair)
        build <- JWTSigSync.signToString[IO, A](
          JWSSignedHeader[A](),
          JWTClaims(issuedAt = Some(Instant.now.plusSeconds(20).getEpochSecond)),
          keyPair.privateKey
        )
        verified <- JWTSigSync.verifyK[IO, A](build, keyPair.publicKey)
      } yield verified

      expression.attempt.unsafeRunSync() mustBe a[Left[Throwable, _]]
    }

    it should "not verify for a wrong nbf" in {
      val expression: IO[JWTSig[A]] = for {
        keyPair <- F.fromEither(kfTag.generateKeyPair)
        build <- JWTSigSync.signToString[IO, A](
          JWSSignedHeader[A](),
          JWTClaims(notBefore = Some(Instant.now.plusSeconds(20).getEpochSecond)),
          keyPair.privateKey
        )
        verified <- JWTSigSync.verifyK[IO, A](build, keyPair.publicKey)
      } yield verified

      expression.attempt.unsafeRunSync() mustBe a[Left[Throwable, _]]
    }

    behavior of s"JWT signature-style ${algoTag.jwtRepr} - SigErrorM"

    it should "Sign and verify properly for proper params" in {
      val expression: Either[Throwable, JWTSig[A]] = for {
        keyPair <- kfTag.generateKeyPair
        build <- JWTSig.signToString(
          JWSSignedHeader[A](),
          JWTClaims(),
          keyPair.privateKey
        )
        verified <- JWTSig.verifyK[A](build, keyPair.publicKey)
      } yield verified

      expression mustBe a[Right[Throwable, _]]
    }

    it should "not verify for an incorrect key" in {
      val expression = for {
        keyPair  <- kfTag.generateKeyPair
        keyPair2 <- kfTag.generateKeyPair
        build <- JWTSig.signToString(
          JWSSignedHeader[A](),
          JWTClaims(issuedAt = Some(Instant.now.minusSeconds(2).getEpochSecond)).withExpiry(5.seconds),
          keyPair.privateKey
        )
        verified <- JWTSig.verifyK(build, keyPair2.publicKey)
      } yield verified

      expression mustBe a[Left[Throwable, _]]
    }

    it should "not verify for an expired claim" in {
      val expression = for {
        keyPair <- kfTag.generateKeyPair
        build <- JWTSig.signToString[A](
          JWSSignedHeader[A](),
          JWTClaims(expiration = Some(Instant.now.minusSeconds(2).getEpochSecond)),
          keyPair.privateKey
        )
        verified <- JWTSig.verifyK[A](build, keyPair.publicKey)
      } yield verified

      expression mustBe a[Left[Throwable, _]]
    }

    it should "not verify for a future iat" in {
      val expression =  for {
        keyPair <- kfTag.generateKeyPair
        build <- JWTSig.signToString(
          JWSSignedHeader[A](),
          JWTClaims(issuedAt = Some(Instant.now.plusSeconds(20).getEpochSecond)),
          keyPair.privateKey
        )
        verified <- JWTSig.verifyK(build, keyPair.publicKey)
      } yield verified

      expression mustBe a[Left[Throwable, _]]
    }

    it should "not verify for a wrong nbf" in {
      val expression = for {
        keyPair <- kfTag.generateKeyPair
        build <- JWTSig.signToString(
          JWSSignedHeader[A](),
          JWTClaims(notBefore = Some(Instant.now.plusSeconds(20).getEpochSecond)),
          keyPair.privateKey
        )
        verified <- JWTSig.verifyK(build, keyPair.publicKey)
      } yield verified

      expression mustBe a[Left[Throwable, _]]
    }
  }

  jwtSigTest[SHA256withRSA]
  jwtSigTest[SHA384withRSA]
  jwtSigTest[SHA512withRSA]
  jwtSigTest[SHA256withECDSA]
  jwtSigTest[SHA384withECDSA]
  jwtSigTest[SHA512withECDSA]
}
