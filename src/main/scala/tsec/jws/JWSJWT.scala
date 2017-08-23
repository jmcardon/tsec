package tsec.jws

import cats.{Functor, Monad}
import tsec.jws.body.{JWSSerializer, JWSSignature}
import tsec.jws.header.JWSJOSE
import tsec.jwt.claims.JWTClaims
import tsec.mac.core.MacPrograms
import tsec.mac.core.MacPrograms.MacAux

case class JWSJWT[A, K[_]](header: JWSJOSE[A, K], body: JWTClaims,  signature: JWSSignature[A])

object JWSJWT {

  implicit def genSigner[F[_]: Monad, A: MacAux, K[_]](implicit hs: JWSSerializer[JWSJOSE[A, K]],
    alg: MacPrograms[F, A, K]) = new JWSMacSigner[F, A, K]() {}
}
