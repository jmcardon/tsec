package tsec.jws.signature

import tsec.jws.{JWSJWT, JWSSignature}
import tsec.jwt.claims.JWTClaims

case class JWTSig[A](header: JWSSignedHeader[A], body: JWTClaims, signature: JWSSignature[A]) extends JWSJWT[A]
