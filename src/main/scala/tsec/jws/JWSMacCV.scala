package tsec.jws

import cats.data.EitherT
import cats.effect.IO
import cats.{Functor, Monad}
import tsec.jws._
import tsec.jws.signature.{JWSSignature, SigVerificationError}
import tsec.jws.header.{JWSJOSE, JWSJOSEMAC}
import tsec.jwt.claims.JWTClaims
import cats.implicits._
import shapeless.{::, HNil}
import tsec.core.ByteUtils
import tsec.mac.MacKey
import tsec.mac.core.{MacPrograms, MacSigningKey}
import tsec.mac.instance.threadlocal.JCATLMacPure
import io.circe.Error
import tsec.core.ByteUtils.ByteAux

sealed abstract class JWSMacCV[F[_], A](
    implicit hs: JWSSerializer[JWSJOSEMAC[A]],
    alg: MacPrograms[F, A, MacKey],
    aux: ByteAux[A],
    M: Monad[F]
) {

  /*
  Generic Error.
  Any mishandling of the errors could leak information to an attacker.
   */
  private def defaultError: SigVerificationError = SigVerificationError("Could not verify signature")

  def signAndBuild(header: JWSJOSEMAC[A], body: JWTClaims, key: MacSigningKey[MacKey[A]]): F[JWTMAC[A]] = {
    val toSign: String = hs.toB64URL(header) + "." + JWTClaims.jwsSerializer.toB64URL(body)
    alg.sign(toSign.asciiBytes, key).map(s => JWTMAC(header, body, JWSSignature(s)))
  }

  def signToString(header: JWSJOSEMAC[A], body: JWTClaims, key: MacSigningKey[MacKey[A]]): F[String] = {
    val toSign: String = hs.toB64URL(header) + "." + JWTClaims.jwsSerializer.toB64URL(body)
    alg.sign(toSign.asciiBytes, key).map(s => toSign + "." + aux.to(s).head.toB64UrlString)
  }

  def verify(jwt: String, key: MacSigningKey[MacKey[A]]): F[Boolean] = {
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
  def verifyAndParse(jwt: String, key: MacSigningKey[MacKey[A]]): EitherT[F, SigVerificationError, JWTMAC[A]] = {
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
      } yield JWTMAC(header, body, JWSSignature(bytes))
    }
  }

  def toEncodedString(jwt: JWTMAC[A]): String =
    hs.toB64URL(jwt.header) + "." + JWTClaims.jwsSerializer.toB64URL(jwt.body) + "." + aux
      .to(jwt.signature.body)
      .head
      .toB64UrlString
}

object JWSMacCV {
  implicit def genSigner[F[_]: Monad, A: ByteAux](
      implicit hs: JWSSerializer[JWSJOSEMAC[A]],
      alg: MacPrograms[F, A, MacKey]
  ): JWSMacCV[F, A] =
    new JWSMacCV[F, A]() {}

  implicit def genSignerIO[F[_]: Monad, A: ByteAux](
      implicit hs: JWSSerializer[JWSJOSEMAC[A]],
      alg: JCATLMacPure[A]
  ): JWSMacCV[IO, A] =
    new JWSMacCV[IO, A]() {}

}
