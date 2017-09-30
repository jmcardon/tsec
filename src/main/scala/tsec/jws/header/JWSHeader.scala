package tsec.jws.header

import tsec.jwt.algorithms.JWA
import tsec.jwt.header.JWTHeader

trait JWSHeader[A] extends JWTHeader {
  def algorithm: JWA[A]
}
