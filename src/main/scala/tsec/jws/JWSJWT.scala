package tsec.jws

import cats.Monad
import tsec.core.ByteUtils
import tsec.jws.header.JWSJOSEMAC.MK
import tsec.jws.signature.JWSSignature
import tsec.jws.header.{JWSJOSE, JWSJOSEMAC}
import tsec.jwt.claims.JWTClaims
import tsec.mac.MacKey
import tsec.mac.core.MacPrograms.MacAux
import tsec.mac.core.MacSigningKey
import tsec.mac.instance.MacTag

case class JWSJWT[A, K[_]](header: JWSJOSE[A, K], body: JWTClaims, signature: JWSSignature[A])

object JWSJWT {

  type JWTMAC[A] = JWSJWT[A, JWSJOSEMAC.MK]

  def signMac[F[_]: Monad, A: MacAux: MacTag, K[_]](header: JWSJOSEMAC[A], body: JWTClaims, key: MacSigningKey[K[A]])(
      implicit s: JWSMacSigner[F, A, K]
  ): F[JWSSignature[A]] = s.sign(header, body, key)

  def signMacToString[F[_]: Monad, A: MacAux: MacTag, K[_]](
      header: JWSJOSEMAC[A],
      body: JWTClaims,
      key: MacSigningKey[K[A]]
  )(implicit s: JWSMacSigner[F, A, K]): F[String] = s.signToString(header, body, key)

  def buildJWT[F[_]: Monad, A: MacAux: MacTag,K[_]](header: JWSJOSEMAC[A], body: JWTClaims, key: MacSigningKey[K[A]])(
      implicit s: JWSMacSigner[F, A, K]
  ): F[JWSJWT[A, MK]] = s.buildJWT(header, body, key)

  def verify[F[_]: Monad, A: MacAux: MacTag, K[_]](jwt: String, key: MacSigningKey[K[A]])(
      implicit s: JWSMacSigner[F, A, K]
  ): F[Boolean] = s.verify(jwt, key)

  def macToEncodedString[F[_]: Monad, A: MacAux: MacTag,K[_]](
      jwt: JWSJWT.JWTMAC[A]
  )(implicit ev: JWSJOSE[A, MK] =:= JWSJOSEMAC[A], s: JWSMacSigner[F, A, K]): String = s.toEncodedString(jwt)

}
