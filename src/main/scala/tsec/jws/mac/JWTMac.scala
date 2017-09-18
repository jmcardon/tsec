package tsec.jws.mac

import java.util.UUID

import cats.Monad
import tsec.core.ByteUtils._
import tsec.jws.{JWSJWT, JWSSerializer}
import tsec.jws.signature.JWSSignature
import tsec.jwt.algorithms.JWTMacAlgo
import tsec.jwt.claims.JWTClaims
import cats.syntax.all._
import io.circe.Json
import tsec.mac.instance.{MacSigningKey, MacTag}

sealed abstract case class JWTMac[A](header: JWSMacHeader[A], body: JWTClaims, signature: JWSSignature[A])
    extends JWSJWT[A]

object JWTMac {
  def apply[F[_]: Monad, A: ByteAux: MacTag](
      claims: JWTClaims,
      key: MacSigningKey[A]
  )(implicit s: JWSMacCV[F, A], algo: JWTMacAlgo[A]): F[JWTMac[A]] = {
    val header = JWSMacHeader[A]
    sign[F, A](header, claims, key).map(sig => buildToken[A](header, claims, sig))
  }

  private[mac] def buildToken[A](header: JWSMacHeader[A], claims: JWTClaims, signature: JWSSignature[A]) =
    new JWTMac[A](header, claims, signature) {}

  def sign[F[_]: Monad, A: ByteAux: MacTag](header: JWSMacHeader[A], body: JWTClaims, key: MacSigningKey[A])(
      implicit s: JWSMacCV[F, A]
  ): F[JWSSignature[A]] = s.signAndBuild(header, body, key)

  def signMacToString[F[_]: Monad, A: ByteAux: MacTag](
      header: JWSMacHeader[A],
      body: JWTClaims,
      key: MacSigningKey[A]
  )(implicit s: JWSMacCV[F, A]): F[String] = s.signToString(header, body, key)

  def verifyMac[F[_]: Monad, A: ByteAux: MacTag](jwt: String, key: MacSigningKey[A])(
      implicit s: JWSMacCV[F, A]
  ): F[Boolean] = s.verify(jwt, key)

  def jwtToEncodedString[F[_]: Monad, A: ByteAux: MacTag](
      jwt: JWTMac[A]
  )(implicit s: JWSMacCV[F, A]): String = s.toEncodedString(jwt)

  def toEncodedString[A](jwt: JWTMac[A])(
      implicit hs: JWSSerializer[JWSMacHeader[A]],
      aux: ByteAux[A]
  ): String =
    hs.toB64URL(jwt.header) + "." + JWTClaims.jwsSerializer.toB64URL(jwt.body) + "." + aux
      .to(jwt.signature.body)
      .head
      .toB64UrlString

}
