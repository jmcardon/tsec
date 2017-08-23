package tsec.jws

import java.nio.charset.StandardCharsets

import cats.{Functor, Monad}
import tsec.jws._
import tsec.jws.body.{JWSSerializer, JWSSignature}
import tsec.jws.header.{JWSJOSE, JWSJOSEMAC}
import tsec.jwt.claims.JWTClaims
import cats.implicits._
import shapeless.{::, HNil}
import tsec.core.ByteUtils
import tsec.jws.header.JWSJOSEMAC.MK
import tsec.mac.core.MacPrograms.MacAux
import tsec.mac.core.{MacPrograms, MacSigningKey}

abstract class JWSMacSigner[F[_]: Monad, A, K[_]](
    implicit hs: JWSSerializer[JWSJOSEMAC[A]],
    val alg: MacPrograms[F, A, K],
    val aux: MacAux[A]
) {
  def sign(header: JWSJOSEMAC[A], body: JWTClaims, key: MacSigningKey[K[A]]): F[JWSSignature[A]] = {
    val toSign: String = hs.toB64URL(header) + "." + JWTClaims.jwsSerializer.toB64URL(body)
    alg.sign(toSign.asciiBytes, key).map(JWSSignature.apply)
  }

  def signToString(header: JWSJOSEMAC[A], body: JWTClaims, key: MacSigningKey[K[A]]): F[String] = {
    val toSign: String = hs.toB64URL(header) + "." + JWTClaims.jwsSerializer.toB64URL(body)
    alg.sign(toSign.asciiBytes, key).map(s => toSign + "." + aux.to(s).head.toB64UrlString)
  }

  def buildJWT(header: JWSJOSEMAC[A], body: JWTClaims, key: MacSigningKey[K[A]]): F[JWSJWT[A, MK]] = {
    val toSign: String = hs.toB64URL(header) + "." + JWTClaims.jwsSerializer.toB64URL(body)
    alg.sign(toSign.asciiBytes, key).map(s => JWSJWT(header, body, JWSSignature(s)))
  }

  def verify(jwt: String, key: MacSigningKey[K[A]]): F[Boolean] = {
    val split: Array[String] = jwt.split(".", 3)
    if (split.length < 3)
      Monad[F].pure(false)
    else {
      val providedBytes: Array[Byte] = split(2).asciiBytes
      alg.algebra
        .sign((split(0) + "." + split(1)).asciiBytes, key)
        .map(b => ByteUtils.arraysEqual(b, providedBytes))
    }
  }

  def toEncodedString(jwt: JWSJWT.JWSMAC[A])(implicit ev: JWSJOSE[A, MK] =:= JWSJOSEMAC[A]): String =
    hs.toB64URL(ev(jwt.header)) + "." + JWTClaims.jwsSerializer.toB64URL(jwt.body) + "." + aux
      .to(jwt.signature.body)
      .head
      .toB64UrlString
}
