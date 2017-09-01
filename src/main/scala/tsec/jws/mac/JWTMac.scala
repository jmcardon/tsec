package tsec.jws.mac

import cats.Monad
import tsec.core.ByteUtils._
import tsec.jws.{JWSJWT, JWSSerializer}
import tsec.jws.signature.JWSSignature
import tsec.jwt.claims.JWTClaims
import tsec.mac.instance.{MacSigningKey, MacTag}

case class JWTMac[A](header: JWSMacHeader[A], body: JWTClaims, signature: JWSSignature[A]) extends JWSJWT[A]

object JWTMac {
  def signMac[F[_]: Monad, A: ByteAux: MacTag](header: JWSMacHeader[A], body: JWTClaims, key: MacSigningKey[A])(
    implicit s: JWSMacCV[F, A]
  ): F[JWTMac[A]] = s.signAndBuild(header, body, key)

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
