package tsec.jws.header

import cats.data.NonEmptyList
import io.circe.{Decoder, Encoder, Error, generic}
import io.circe.syntax._
import tsec.jws._
import tsec.jws.algorithms.{JWTAlgorithm, JWTMacAlgo}
import tsec.jws.body.JWSSerializer
import tsec.jwt
import tsec.jwt.header.JWTHeader
import tsec.mac.MacKey
import tsec.mac.core.MacSigningKey
import tsec.mac.instance.MacTag

sealed trait JWSJOSE[A, K[_]] extends JWTHeader {
  def algorithm: JWTAlgorithm[A, K]
}

case class JWSJOSEMAC[A: MacTag](
    `type`: Option[String], //Type, which will almost always default to "JWT"
    algorithm: JWTMacAlgo[A], //Algorithm, in this case a MAC
    contentType: Option[String], // Optional header, preferrably not used
    critical: Option[NonEmptyList[String]] //Headers not to ignore, they must be understood by the JWT implementation
) extends JWSJOSE[A, λ[A => MacSigningKey[MacKey[A]]]]

object JWSJOSEMAC {
  implicit def serializer[A: MacTag](implicit d: Decoder[JWSJOSEMAC[A]],
    e: Encoder[JWSJOSEMAC[A]]) = new JWSSerializer[JWSJOSEMAC[A]] {
    def serializeUtf8(body: JWSJOSEMAC[A]): Array[Byte] = jwt.JWTPrinter.pretty(body.asJson).utf8Bytes

    def fromUtf8Bytes(array: Array[Byte]): Either[Error, JWSJOSEMAC[A]] =
      io.circe.parser.decode[JWSJOSEMAC[A]](array.toUtf8String)
  }
}
