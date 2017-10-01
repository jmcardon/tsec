package tsec.jws

import tsec.jws.header.JWSHeader
import tsec.jwt.claims.JWTClaims

trait JWSJWT[A] {
  def header: JWSHeader[A]

  def body: JWTClaims

  def signature: JWSSignature[A]
}
