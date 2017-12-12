package tsec.jws

import tsec.jws.header.JWSHeader
import tsec.jwt.JWTClaims

trait JWSJWT[A, Sig[_]] {
  def header: JWSHeader[A]

  def body: JWTClaims

  def signature: Sig[A]
}
