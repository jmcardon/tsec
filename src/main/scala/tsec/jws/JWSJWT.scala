package tsec.jws

import cats.{Functor, Monad}
import tsec.jws.body.{JWSSerializer, JWSSignature}
import tsec.jws.header.{JWSJOSE, JWSJOSEMAC}
import tsec.jwt.claims.JWTClaims
import tsec.mac.MacKey
import tsec.mac.core.{MacPrograms, MacSigningKey}
import tsec.mac.core.MacPrograms.MacAux

case class JWSJWT[A, K[_]](header: JWSJOSE[A, K], body: JWTClaims, signature: JWSSignature[A])

object JWSJWT {

  implicit def genSigner[F[_]: Monad, A: MacAux, K[_]](
      implicit hs: JWSSerializer[JWSJOSEMAC[A]],
      alg: MacPrograms[F, A, K]
  ): JWSMacSigner[F, A, K] = {
    new JWSMacSigner[F, A, K]() {}
  }

  type JWSMAC[A] = JWSJWT[A, JWSJOSEMAC.MK]

}
