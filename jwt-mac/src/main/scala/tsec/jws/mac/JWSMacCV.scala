package tsec.jws.mac

import java.security.MessageDigest
import java.time.Instant

import cats.MonadError
import cats.effect.Sync
import cats.implicits._
import tsec.common._
import tsec.jws._
import tsec.jwt.JWTClaims
import tsec.mac.{MessageAuth, _}
import tsec.mac.jca._

/** Our JWS Compressor, Signer and verifier (CV = Compressor and Verifier)
  *
  * @param hs our header serializer
  * @param programs our mac program implementation
  * @param M Monad instance for F
  * @tparam F Our effect type
  * @tparam A The mac signing algorithm
  */
sealed abstract class JWSMacCV[F[_], A](
    implicit hs: JWSSerializer[JWSMacHeader[A]],
    programs: MessageAuth[F, A, MacSigningKey],
    M: MonadError[F, Throwable]
) {

  /**  Generic Error. Any mishandling of the errors could leak information to an attacker. */
  private[this] def defaultError: MacError = MacVerificationError("Could not verify signature")

  private[this] def base64Safe(s: String): Either[Throwable, Array[Byte]] =
    s.b64UrlBytes match {
      case Some(b) => Right(b)
      case None    => Left(defaultError)
    }

  private[this] def base64SafeF(s: String): F[Array[Byte]] =
    s.b64UrlBytes match {
      case Some(b) => M.pure(b)
      case None    => M.raiseError(defaultError)
    }

  def sign(header: JWSMacHeader[A], body: JWTClaims, key: MacSigningKey[A]): F[MAC[A]] = {
    val toSign: String = hs.toB64URL(header) + "." + JWTClaims.toB64URL(body)
    programs.sign(toSign.asciiBytes, key)
  }

  def signAndBuild(header: JWSMacHeader[A], body: JWTClaims, key: MacSigningKey[A]): F[JWTMac[A]] = {
    val toSign: String = hs.toB64URL(header) + "." + JWTClaims.toB64URL(body)
    programs.sign(toSign.asciiBytes, key).map(s => JWTMac.buildToken[A](header, body, s))
  }

  def signToString(header: JWSMacHeader[A], body: JWTClaims, key: MacSigningKey[A]): F[String] = {
    val toSign: String = hs.toB64URL(header) + "." + JWTClaims.toB64URL(body)
    programs.sign(toSign.asciiBytes, key).map(s => toSign + "." + s.toB64UrlString)
  }

  def verifyBool(jwt: String, key: MacSigningKey[A], now: Instant): F[Boolean] = {
    val split: Array[String] = jwt.split("\\.", 3)
    if (split.length < 3)
      M.pure(false)
    else {
      split(2).b64UrlBytes match {
        case Some(providedBytes) =>
          (for {
            bytes  <- base64Safe(split(0))
            _      <- hs.fromUtf8Bytes(bytes)
            cBytes <- base64Safe(split(1))
            claims <- JWTClaims.fromUtf8Bytes(cBytes)
          } yield claims).fold(
            _ => M.pure(false),
            claims =>
              programs
                .sign((split(0) + "." + split(1)).asciiBytes, key)
                .map {
                  MessageDigest.isEqual(_, providedBytes) && claims.isNotExpired(now) && claims
                    .isAfterNBF(now) && claims.isValidIssued(now)
              }
          )
        case None =>
          M.pure(false)
      }
    }
  }

  def verify(jwt: String, key: MacSigningKey[A], now: Instant): F[VerificationStatus] =
    verifyBool(jwt, key, now).map(c => if (c) Verified else VerificationFailed)

  def verifyAndParse(jwt: String, key: MacSigningKey[A], now: Instant): F[JWTMac[A]] = {
    val split = jwt.split("\\.", 3)
    if (split.length != 3)
      M.raiseError(defaultError)
    else {
      split(2).b64UrlBytes match {
        case Some(signedBytes) =>
          for {
            hBytes <- base64SafeF(split(0))
            header <- M.fromEither(hs.fromUtf8Bytes(hBytes).left.map(_ => defaultError))
            claims <- M.fromEither(JWTClaims.fromB64URL(split(1)).left.map(_ => defaultError))
            bytes <- M.ensure(programs.sign((split(0) + "." + split(1)).asciiBytes, key))(defaultError)(
              signed =>
                MessageDigest.isEqual(signed, signedBytes)
                  && claims.isNotExpired(now)
                  && claims.isAfterNBF(now)
                  && claims.isValidIssued(now)
            )
          } yield JWTMac.buildToken[A](header, claims, bytes)
        case None => M.raiseError(defaultError)
      }
    }
  }

  def toEncodedString(jwt: JWTMac[A]): String =
    hs.toB64URL(jwt.header) + "." + JWTClaims.toB64URL(jwt.body) + "." + jwt.signature.toB64UrlString

  def parseUnverified(jwt: String): F[JWTMac[A]] = {
    val split = jwt.split("\\.", 3)
    if (split.length != 3)
      M.raiseError(defaultError)
    else {
      for {
        signedBytes <- base64SafeF(split(2))
        hBytes      <- base64SafeF(split(0))
        header      <- M.fromEither(hs.fromUtf8Bytes(hBytes).left.map(_ => defaultError))
        claims      <- M.fromEither(JWTClaims.fromB64URL(split(1)).left.map(_ => defaultError))
      } yield JWTMac.buildToken[A](header, claims, MAC[A](signedBytes))
    }
  }
}

object JWSMacCV {

  implicit def genSigner[F[_]: Sync, A](
      implicit hs: JWSSerializer[JWSMacHeader[A]],
      messageAuth: MessageAuth[F, A, MacSigningKey]
  ): JWSMacCV[F, A] =
    new JWSMacCV[F, A]() {}

  implicit def eitherSigner[A](
      implicit hs: JWSSerializer[JWSMacHeader[A]],
      messageAuth: MessageAuth[MacErrorM, A, MacSigningKey]
  ): JWSMacCV[MacErrorM, A] =
    new JWSMacCV[({type F[A] = Either[Throwable, A]})#F, A]() {}

}
