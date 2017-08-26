package tsec.jws

import java.nio.charset.StandardCharsets

import cats.effect.IO
import cats.{Functor, Monad}
import tsec.jws._
import tsec.jws.signature.JWSSignature
import tsec.jws.header.{JWSJOSE, JWSJOSEMAC}
import tsec.jwt.claims.JWTClaims
import cats.implicits._
import shapeless.{::, HNil}
import tsec.core.ByteUtils
import tsec.mac.MacKey
import tsec.mac.core.MacPrograms.MacAux
import tsec.mac.core.{MacPrograms, MacSigningKey}
import tsec.mac.instance.threadlocal.JCATLMacPure

sealed abstract class JWSMacSigner[F[_], A](
    implicit hs: JWSSerializer[JWSJOSEMAC[A]],
    alg: MacPrograms[F, A, MacKey],
    aux: MacAux[A],
    M: Monad[F]
) {
  def sign(header: JWSJOSEMAC[A], body: JWTClaims, key: MacSigningKey[MacKey[A]]): F[JWSSignature[A]] = {
    val toSign: String = hs.toB64URL(header) + "." + JWTClaims.jwsSerializer.toB64URL(body)
    alg.sign(toSign.asciiBytes, key).map(JWSSignature.apply)
  }

  def signToString(header: JWSJOSEMAC[A], body: JWTClaims, key: MacSigningKey[MacKey[A]]): F[String] = {
    val toSign: String = hs.toB64URL(header) + "." + JWTClaims.jwsSerializer.toB64URL(body)
    alg.sign(toSign.asciiBytes, key).map(s => toSign + "." + aux.to(s).head.toB64UrlString)
  }

  def buildJWT(header: JWSJOSEMAC[A], body: JWTClaims, key: MacSigningKey[MacKey[A]]): F[JWTMAC[A]] = {
    val toSign: String = hs.toB64URL(header) + "." + JWTClaims.jwsSerializer.toB64URL(body)
    alg.sign(toSign.asciiBytes, key).map(s => JWTMAC(header, body, JWSSignature(s)))
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
              .map(b => ByteUtils.arraysEqual(b, providedBytes))
        )
    }
  }

  def toEncodedString(jwt: JWTMAC[A]): String =
    hs.toB64URL(jwt.header) + "." + JWTClaims.jwsSerializer.toB64URL(jwt.body) + "." + aux
      .to(jwt.signature.body)
      .head
      .toB64UrlString
}

object JWSMacSigner {
  implicit def genSigner[F[_]: Monad, A: MacAux](
      implicit hs: JWSSerializer[JWSJOSEMAC[A]],
      alg: MacPrograms[F, A, MacKey]
  ): JWSMacSigner[F, A] =
    new JWSMacSigner[F, A]() {}

  implicit def genSignerIO[F[_]: Monad, A: MacAux](
      implicit hs: JWSSerializer[JWSJOSEMAC[A]],
      alg: JCATLMacPure[A]
  ): JWSMacSigner[IO, A] =
    new JWSMacSigner[IO, A]() {}

}
