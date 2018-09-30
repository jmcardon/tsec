package tsec.jws.signature

import java.time.Instant

import cats.MonadError
import cats.effect.Sync
import cats.instances.either._
import cats.syntax.all._
import tsec.common._
import tsec.jws.JWSSerializer
import tsec.jwt.JWTClaims
import tsec.jwt.algorithms.JWTSigAlgo
import tsec.signature._
import tsec.signature.jca._

sealed abstract class JWSSigCV[F[_], A](
    implicit hs: JWSSerializer[JWSSignedHeader[A]],
    jwsSigAlgo: JWTSigAlgo[A],
    sigDSL: JCASigner[F, A],
    M: MonadError[F, Throwable]
) {

  /** Generic Error. Any mishandling of the errors could leak information to an attacker.*/
  private def defaultError: GeneralSignatureError = GeneralSignatureError("Could not verify signature")

  private[this] def base64UrlSafe(s: String): Either[GeneralSignatureError, Array[Byte]] =
    s.b64UrlBytes match {
      case Some(b) => Right(b)
      case None    => Left(defaultError)
    }

  private[this] def base64UrlSafeF(s: String): F[Array[Byte]] =
    s.b64UrlBytes match {
      case Some(b) =>
        M.pure(b)
      case None =>
        M.raiseError(defaultError)
    }

  def signAndBuild(header: JWSSignedHeader[A], body: JWTClaims, sigPrivateKey: SigPrivateKey[A]): F[JWTSig[A]] = {
    val toSign = hs.toB64URL(header) + "." + JWTClaims.toB64URL(body)
    for {
      signature <- sigDSL.sign(toSign.asciiBytes, sigPrivateKey)
      concat    <- jwsSigAlgo.jcaToConcat[F](signature)
    } yield JWTSig(header, body, CryptoSignature[A](concat))
  }

  def signToString(header: JWSSignedHeader[A], body: JWTClaims, sigPrivateKey: SigPrivateKey[A]): F[String] = {
    val toSign = hs.toB64URL(header) + "." + JWTClaims.toB64URL(body)
    for {
      signature <- sigDSL.sign(toSign.asciiBytes, sigPrivateKey)
      concat    <- jwsSigAlgo.jcaToConcat[F](signature)
    } yield toSign + "." + concat.toB64UrlString
  }

  def verify(
      jwt: String,
      pubKey: SigPublicKey[A],
      now: Instant
  ): F[JWTSig[A]] = {
    val split: Array[String] = jwt.split("\\.", 3)
    if (split.length != 3)
      M.raiseError[JWTSig[A]](defaultError)
    else {
      val toSign = (split(0) + "." + split(1)).asciiBytes
      for {
        providedBytes <- base64UrlSafeF(split(2))
        sigExtract    <- jwsSigAlgo.concatToJCA[F](providedBytes)
        headerBytes   <- base64UrlSafeF(split(0))
        header        <- M.fromEither(hs.fromUtf8Bytes(headerBytes).left.map(_ => {println("kekistan1"); defaultError}))
        bool          <- sigDSL.verifyBool(toSign, CryptoSignature[A](sigExtract), pubKey)
        body <- M.ensure(M.fromEither(JWTClaims.fromB64URL(split(1))))(defaultError)(
          claims => bool && claims.isAfterNBF(now) && claims.isNotExpired(now) && claims.isValidIssued(now)
        )
      } yield JWTSig(header, body, CryptoSignature[A](providedBytes))
    }
  }

  def extractRaw(jwt: String): F[JWTSig[A]] = {
    val split: Array[String] = jwt.split("\\.", 3)
    if (split.length != 3)
      M.raiseError[JWTSig[A]](defaultError)
    else {
      val providedBytes: Array[Byte] = split(2).base64UrlBytes
      for {
        header <- M.fromEither(hs.fromUtf8Bytes(split(0).base64UrlBytes).left.map(_ => defaultError))
        body   <- M.fromEither(JWTClaims.fromB64URL(split(1)))
      } yield JWTSig(header, body, CryptoSignature[A](providedBytes))
    }
  }

  def verifyCert(
      jwt: String,
      cert: SigCertificate[A],
      now: Instant
  ): F[JWTSig[A]] = {
    val split: Array[String] = jwt.split("\\.", 3)
    if (split.length != 3)
      M.raiseError[JWTSig[A]](defaultError)
    else {
      val toSign = (split(0) + "." + split(1)).asciiBytes
      for {
        providedBytes <- base64UrlSafeF(split(2))
        sigExtract    <- jwsSigAlgo.concatToJCA[F](providedBytes)
        headerBytes   <- base64UrlSafeF(split(0))
        header        <- M.fromEither(hs.fromUtf8Bytes(headerBytes).left.map(_ => {println("kekistan2"); defaultError}))
        bool          <- sigDSL.verifyCert(toSign, CryptoSignature[A](sigExtract), cert)
        body <- M.ensure(M.fromEither(JWTClaims.fromB64URL(split(1))))(defaultError)(
          claims => bool && claims.isAfterNBF(now) && claims.isNotExpired(now) && claims.isValidIssued(now)
        )
      } yield JWTSig(header, body, CryptoSignature[A](providedBytes))
    }
  }
}

object JWSSigCV {
  implicit def genCVPure[F[_]: Sync, A](
      implicit hs: JWSSerializer[JWSSignedHeader[A]],
      signer: JCASigner[F, A],
      jwsSigAlgo: JWTSigAlgo[A]
  ): JWSSigCV[F, A] = new JWSSigCV[F, A]() {}

  implicit def genCVImpure[A](
      implicit hs: JWSSerializer[JWSSignedHeader[A]],
      signer: JCASigner[SigErrorM, A],
      jwsSigAlgo: JWTSigAlgo[A]
  ): JWSSigCV[SigErrorM, A] = new JWSSigCV[SigErrorM, A]() {}
}
