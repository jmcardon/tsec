package tsec.jws

import cats.Monad
import tsec.core.ByteUtils
import tsec.jws.header.JWSJOSEMAC.MK
import tsec.jws.signature.JWSSignature
import tsec.jws.header.{JWSJOSE, JWSJOSEMAC}
import tsec.jwt.claims.JWTClaims
import tsec.mac.MacKey
import tsec.mac.core.MacPrograms.MacAux
import tsec.mac.core.{MacPrograms, MacSigningKey}
import tsec.mac.instance.MacTag

sealed trait JWSJWT[A, K[_]]{
  def header: JWSJOSE[A]
  def body: JWTClaims
  def signature: JWSSignature[A]
}

case class JWTMAC[A](header: JWSJOSEMAC[A], body: JWTClaims, signature: JWSSignature[A]) extends JWSJWT[A, JWSJOSEMAC.MK]

object JWTMAC {
  def signMac[F[_]: Monad, A: MacAux: MacTag](header: JWSJOSEMAC[A], body: JWTClaims, key: MacSigningKey[MacKey[A]])(
    implicit s: JWSMacSigner[F, A]
  ): F[JWSSignature[A]] = s.sign(header, body, key)

  def signMacToString[F[_]: Monad, A: MacAux: MacTag](
    header: JWSJOSEMAC[A],
    body: JWTClaims,
    key: MacSigningKey[MacKey[A]]
  )(implicit s: JWSMacSigner[F, A]): F[String] = s.signToString(header, body, key)

  def buildJWT[F[_]: Monad, A: MacAux: MacTag](header: JWSJOSEMAC[A], body: JWTClaims, key: MacSigningKey[MacKey[A]])(
    implicit s: JWSMacSigner[F, A]
  ): F[JWTMAC[A]] = s.buildJWT(header, body, key)

  def verifyMac[F[_]: Monad, A: MacAux: MacTag](jwt: String, key: MacSigningKey[MacKey[A]])(
    implicit s: JWSMacSigner[F, A]
  ): F[Boolean] = s.verify(jwt, key)

  def jwtToEncodedString[F[_]: Monad, A: MacAux: MacTag](
    jwt: JWTMAC[A]
  )(implicit s: JWSMacSigner[F, A]): String = s.toEncodedString(jwt)

  def toEncodedString[A](jwt: JWTMAC[A])(
    implicit hs: JWSSerializer[JWSJOSEMAC[A]],
    aux: MacAux[A]
  ): String =
    hs.toB64URL(jwt.header) + "." + JWTClaims.jwsSerializer.toB64URL(jwt.body) + "." + aux
      .to(jwt.signature.body)
      .head
      .toB64UrlString
}