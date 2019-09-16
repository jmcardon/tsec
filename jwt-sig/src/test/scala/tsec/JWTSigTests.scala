package tsec

import java.security.Security
import java.time.Instant

import cats.effect.IO
import cats.syntax.either._
import org.bouncycastle.jce.provider.BouncyCastleProvider
import tsec.jws.signature._
import tsec.jwt.JWTClaims
import tsec.jwt.algorithms.JWTSigAlgo
import tsec.signature.jca._

class JWTSigTests extends TestSpec {

  if (Security.getProvider("BC") == null)
    Security.addProvider(new BouncyCastleProvider())

  def jwtSigTest[A](
      implicit algoTag: JWTSigAlgo[A],
      kfTag: JCASigKG[IO, A],
      kfSigError: JCASigKG[SigErrorM, A],
      cv: JWSSigCV[IO, A],
      cv2: JWSSigCV[SigErrorM, A]
  ) = {
    behavior of s"JWT signature-style ${algoTag.jwtRepr} - pure"

    it should "Sign and verify properly for proper params" in {
      val expression: IO[JWTSig[A]] = for {
        now     <- IO(Instant.now())
        keyPair <- kfTag.generateKeyPair
        build <- JWTSig.signToString[IO, A](
          JWSSignedHeader[A](),
          JWTClaims(issuedAt = Some(now.minusSeconds(2)), expiration = Some(now.plusSeconds(25))),
          keyPair.privateKey
        )
        verified <- JWTSig.verifyK[IO, A](build, keyPair.publicKey)
      } yield verified

      expression.unsafeRunSync() mustBe a[JWTSig[_]]
    }

    it should "not verify for an incorrect key" in {
      val expression: IO[JWTSig[A]] = for {
        now      <- IO(Instant.now())
        keyPair  <- kfTag.generateKeyPair
        keyPair2 <- kfTag.generateKeyPair
        build <- JWTSig.signToString[IO, A](
          JWSSignedHeader[A](),
          JWTClaims(issuedAt = Some(now.minusSeconds(2)), expiration = Some(now.plusSeconds(5))),
          keyPair.privateKey
        )
        verified <- JWTSig.verifyK[IO, A](build, keyPair2.publicKey)
      } yield verified

      expression.attempt.unsafeRunSync() mustBe a[Left[Throwable, _]]
    }

    it should "not verify for an expired claim" in {
      val expression: IO[JWTSig[A]] = for {
        keyPair <- kfTag.generateKeyPair
        now     <- IO(Instant.now)
        build <- JWTSig.signToString[IO, A](
          JWSSignedHeader[A](),
          JWTClaims(expiration = Some(now.minusSeconds(2))),
          keyPair.privateKey
        )
        verified <- JWTSig.verifyK[IO, A](build, keyPair.publicKey)
      } yield verified

      expression.attempt.unsafeRunSync() mustBe a[Left[Throwable, _]]
    }

    it should "not verify for a future iat" in {
      val expression: IO[JWTSig[A]] = for {
        keyPair <- kfTag.generateKeyPair
        now     <- IO(Instant.now)
        build <- JWTSig.signToString[IO, A](
          JWSSignedHeader[A](),
          JWTClaims(issuedAt = Some(now.plusSeconds(20))),
          keyPair.privateKey
        )
        verified <- JWTSig.verifyK[IO, A](build, keyPair.publicKey)
      } yield verified

      expression.attempt.unsafeRunSync() mustBe a[Left[Throwable, _]]
    }

    it should "not verify for a wrong nbf" in {
      val expression: IO[JWTSig[A]] = for {
        keyPair <- kfTag.generateKeyPair
        now     <- IO(Instant.now)
        build <- JWTSig.signToString[IO, A](
          JWSSignedHeader[A](),
          JWTClaims(notBefore = Some(now.plusSeconds(20))),
          keyPair.privateKey
        )
        verified <- JWTSig.verifyK[IO, A](build, keyPair.publicKey)
      } yield verified

      expression.attempt.unsafeRunSync() mustBe a[Left[Throwable, _]]
    }

    behavior of s"JWT signature-style ${algoTag.jwtRepr} - SigErrorM"

    it should "Sign and verify properly for proper params" in {
      val expression: Either[Throwable, JWTSig[A]] = for {
        keyPair <- kfSigError.generateKeyPair
        build <- JWTSigImpure.signToString(
          JWSSignedHeader[A](),
          JWTClaims(),
          keyPair.privateKey
        )
        verified <- JWTSigImpure.verifyK[A](build, keyPair.publicKey)
      } yield verified

      expression mustBe a[Right[Throwable, _]]
    }

    it should "not verify for an incorrect key" in {
      val now = Instant.now()

      val expression = for {
        keyPair  <- kfSigError.generateKeyPair
        keyPair2 <- kfSigError.generateKeyPair
        build <- JWTSigImpure.signToString[A](
          JWSSignedHeader[A](),
          JWTClaims(issuedAt = Some(now.minusSeconds(2)), expiration = Some(now.plusSeconds(5))),
          keyPair.privateKey
        )
        verified <- JWTSigImpure.verifyK(build, keyPair2.publicKey)
      } yield verified

      expression mustBe a[Left[Throwable, _]]
    }

    it should "not verify for an expired claim" in {
      val now = Instant.now()

      val expression = for {
        keyPair <- kfSigError.generateKeyPair
        build <- JWTSigImpure.signToString[A](
          JWSSignedHeader[A](),
          JWTClaims(expiration = Some(now.minusSeconds(2))),
          keyPair.privateKey
        )
        verified <- JWTSigImpure.verifyK[A](build, keyPair.publicKey)
      } yield verified

      expression mustBe a[Left[Throwable, _]]
    }

    it should "not verify for a future iat" in {
      val now = Instant.now()

      val expression = for {
        keyPair <- kfSigError.generateKeyPair
        build <- JWTSigImpure.signToString(
          JWSSignedHeader[A](),
          JWTClaims(issuedAt = Some(now.plusSeconds(20))),
          keyPair.privateKey
        )
        verified <- JWTSigImpure.verifyK(build, keyPair.publicKey)
      } yield verified

      expression mustBe a[Left[Throwable, _]]
    }

    it should "not verify for a wrong nbf" in {
      val now = Instant.now()

      val expression = for {
        keyPair <- kfSigError.generateKeyPair
        build <- JWTSigImpure.signToString(
          JWSSignedHeader[A](),
          JWTClaims(notBefore = Some(now.plusSeconds(20))),
          keyPair.privateKey
        )
        verified <- JWTSigImpure.verifyK(build, keyPair.publicKey)
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
