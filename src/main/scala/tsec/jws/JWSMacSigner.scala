package tsec.jws

import java.nio.charset.StandardCharsets

import cats.{Functor, Monad}
import tsec.jws._
import tsec.jws.body.{JWSSerializer, JWSSignature}
import tsec.jws.header.JWSJOSE
import tsec.jwt.claims.JWTClaims
import cats.implicits._
import tsec.core.ByteUtils
import tsec.mac.core.MacPrograms.MacAux
import tsec.mac.core.{MacPrograms, MacSigningKey}

abstract class JWSMacSigner[F[_]: Monad, A: MacAux, K[_]](
    implicit hs: JWSSerializer[JWSJOSE[A, K]],
    alg: MacPrograms[F, A, K]
) {
  def sign(header: JWSJOSE[A, K], body: JWTClaims, key: MacSigningKey[K[A]]): F[JWSSignature[A]] = {
    val toSign: String = hs.toB64URL(header) + "." + JWTClaims.jwsSerializer.toB64URL(body)
    alg.sign(toSign.asciiBytes, key).map(JWSSignature.apply)
  }

  def verify(jwt: String, key: MacSigningKey[K[A]]): F[Boolean] = {
    val split: Array[String] = jwt.split(".", 3)
    if (split.length < 3)
      Monad[F].pure(false)
    else {
      val providedBytes: Array[Byte] = split(2).asciiBytes
      alg.algebra
        .sign((split(0) + "." + split(1)).asciiBytes, key)
        .map(b => ByteUtils.arraysEqual(b, providedBytes))
    }
  }
}
