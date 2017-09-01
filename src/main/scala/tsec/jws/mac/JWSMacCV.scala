package tsec.jws.mac

import cats.Monad
import cats.data.EitherT
import cats.effect.IO
import cats.implicits._
import tsec.core.ByteUtils
import tsec.core.ByteUtils._
import tsec.jws._
import tsec.jws.signature.{JWSSignature, SigVerificationError}
import tsec.jwt.claims.JWTClaims
import tsec.mac.core.MacPrograms
import tsec.mac.instance.MacSigningKey
import tsec.mac.instance.threadlocal.JCATLMacPure

sealed abstract class JWSMacCV[F[_], A](
                                         implicit hs: JWSSerializer[JWSMacHeader[A]],
                                         alg: MacPrograms[F, A, MacSigningKey],
                                         aux: ByteAux[A],
                                         M: Monad[F]
) {

  /*
  Generic Error.
  Any mishandling of the errors could leak information to an attacker.
   */
  private def defaultError: SigVerificationError = SigVerificationError("Could not verify signature")

  def signAndBuild(header: JWSMacHeader[A], body: JWTClaims, key: MacSigningKey[A]): F[JWTMac[A]] = {
    val toSign: String = hs.toB64URL(header) + "." + JWTClaims.jwsSerializer.toB64URL(body)
    alg.sign(toSign.asciiBytes, key).map(s => JWTMac(header, body, JWSSignature(s)))
  }

  def signToString(header: JWSMacHeader[A], body: JWTClaims, key: MacSigningKey[A]): F[String] = {
    val toSign: String = hs.toB64URL(header) + "." + JWTClaims.jwsSerializer.toB64URL(body)
    alg.sign(toSign.asciiBytes, key).map(s => toSign + "." + aux.to(s).head.toB64UrlString)
  }

  def verify(jwt: String, key: MacSigningKey[A]): F[Boolean] = {
    val split: Array[String] = jwt.split("\\.", 3)
    if (split.length < 3)
      M.pure(false)
    else {
      val providedBytes: Array[Byte] = split(2).base64Bytes
      hs.fromUtf8Bytes(split(0).base64Bytes)
        .fold(
          _ => M.pure(false),
          _ =>
            alg.algebra
              .sign((split(0) + "." + split(1)).asciiBytes, key)
              .map(b => ByteUtils.constantTimeEquals(b, providedBytes))
        )
    }
  }

  /*
  Todo: Cleanup
   */
  def verifyAndParse(jwt: String, key: MacSigningKey[A]): EitherT[F, SigVerificationError, JWTMac[A]] = {
    val split: Array[String] = jwt.split("\\.", 3)
    if (split.length != 3)
      EitherT.left(M.pure(defaultError))
    else {
      val signedBytes: Array[Byte] = split(2).base64Bytes
      for {
        header <- EitherT
          .fromEither[F](hs.fromUtf8Bytes(split(0).base64Bytes))
          .leftMap(_ => defaultError)
        bytes <- EitherT.liftT(alg.sign((split(0) + "." + split(1)).asciiBytes, key))
        _ <- EitherT
          .cond[F](ByteUtils.constantTimeEquals(aux.to(bytes).head, signedBytes), (), defaultError)
        body <- EitherT
          .fromEither[F](
            JWTClaims.jwsSerializer
              .fromB64URL(split(1)))
          .leftMap(_ => defaultError)
      } yield JWTMac(header, body, JWSSignature(bytes))
    }
  }

  def toEncodedString(jwt: JWTMac[A]): String =
    hs.toB64URL(jwt.header) + "." + JWTClaims.jwsSerializer.toB64URL(jwt.body) + "." + aux
      .to(jwt.signature.body)
      .head
      .toB64UrlString
}

object JWSMacCV {
  implicit def genSigner[F[_]: Monad, A: ByteAux](
                                                   implicit hs: JWSSerializer[JWSMacHeader[A]],
                                                   alg: MacPrograms[F, A, MacSigningKey]
  ): JWSMacCV[F, A] =
    new JWSMacCV[F, A]() {}

  implicit def genSignerIO[F[_]: Monad, A: ByteAux](
                                                     implicit hs: JWSSerializer[JWSMacHeader[A]],
                                                     alg: JCATLMacPure[A]
  ): JWSMacCV[IO, A] =
    new JWSMacCV[IO, A]() {}

}
