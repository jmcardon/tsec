package tsec.jws.signature

import tsec.jws.JWSJWT
import tsec.jws.header.JWSSignedHeader
import tsec.jwt.claims.JWTClaims

case class JWTSig[A](header: JWSSignedHeader[A], body: JWTClaims, signature: JWSSignature[A]) extends JWSJWT[A]
