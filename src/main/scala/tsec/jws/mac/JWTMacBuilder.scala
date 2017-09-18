package tsec.jws.mac

import java.util.UUID

import cats.Monad
import io.circe.Json
import tsec.core.ByteUtils.ByteAux
import tsec.jwt.algorithms.JWTMacAlgo
import tsec.jwt.claims.JWTClaims
import tsec.mac.instance.{MacSigningKey, MacTag}

object JWTMacBuilder {
  def build[F[_]: Monad, A: ByteAux: MacTag](
      issuer: Option[String] = None,
      subject: Option[String] = None,
      audience: Option[Either[String, List[String]]] = None,
      expiration: Option[Long] = None,
      notBefore: Option[Long] = None,
      issuedAt: Option[Long] = Some(System.currentTimeMillis()),
      jwtId: Option[String] = Some(UUID.randomUUID().toString),
      custom: Json = Json.Null
  )(key: MacSigningKey[A])(implicit s: JWSMacCV[F, A], algo: JWTMacAlgo[A]) =
    JWTMac[F, A](JWTClaims(issuer, subject, audience, expiration, notBefore, issuedAt, jwtId, custom), key)

}
