package tsec.jws.header

import cats.data.NonEmptyList
import io.circe.syntax._
import io.circe.{Decoder, DecodingFailure, Encoder, Error, HCursor, Json}
import tsec.jws.{JWSSerializer, _}
import tsec.jws.algorithms.{JWTAlgorithm, JWTMacAlgo}
import tsec.jwt
import tsec.jwt.header.JWTHeader
import tsec.mac.MacKey
import tsec.mac.core.MacSigningKey
import tsec.mac.instance.MacTag

sealed trait JWSJOSE[A, K[_]] extends JWTHeader {
  def algorithm: JWTAlgorithm[A]
}

sealed abstract case class JWSJOSEMAC[A: MacTag](
    `type`: Option[String] = Some("JWT"), //Type, which will almost always default to "JWT"
    algorithm: JWTMacAlgo[A], //Algorithm, in this case a MAC
    contentType: Option[String] = None, // Optional header, preferably not used
    critical: Option[NonEmptyList[String]] = None //Headers not to ignore, they must be understood by the JWT implementation
) extends JWSJOSE[A, JWSJOSEMAC.MK]

object JWSJOSEMAC {
  type MK[A]  = MacSigningKey[MacKey[A]]


  def jwtHeader[A: MacTag](implicit jwtMacAlgo: JWTMacAlgo[A]) =
    new JWSJOSEMAC[A](
      algorithm = jwtMacAlgo
    ) {}

  implicit def encoder[A: MacTag] = new Encoder[JWSJOSEMAC[A]] {
    def apply(a: JWSJOSEMAC[A]): Json = Json.obj(
      ("typ", a.`type`.asJson),
      ("alg", a.algorithm.jwtRepr.asJson),
      ("cty", a.contentType.asJson),
      ("crit", a.critical.asJson)
    )
  }

  implicit def decoder[A: MacTag: JWTMacAlgo]: Decoder[JWSJOSEMAC[A]] = new Decoder[JWSJOSEMAC[A]] {
    def apply(c: HCursor): Either[DecodingFailure, JWSJOSEMAC[A]] =
      c.downField("alg")
        .as[Option[String]]
        .map(f => JWTMacAlgo.fromString[A](f.getOrElse(""))) match {
        case Right(opt) =>
          opt match {
            case Some(o) =>
              for {
                t     <- c.downField("typ").as[Option[String]]
                cType <- c.downField("cty").as[Option[String]]
                crit  <- c.downField("crit").as[Option[NonEmptyList[String]]]
              } yield
                new JWSJOSEMAC[A](
                  `type` = t,
                  algorithm = o,
                  contentType = cType,
                  critical = crit
                ) {}
            case None =>
              Left(DecodingFailure("No algorithm found", Nil))
          }

        case Left(d) => Left(d)
      }
  }

  implicit def genSerializer[A: MacTag](implicit d: Decoder[JWSJOSEMAC[A]], e: Encoder[JWSJOSEMAC[A]]): JWSSerializer[JWSJOSEMAC[A]] =
    new JWSSerializer[JWSJOSEMAC[A]] {
      def serializeUtf8(body: JWSJOSEMAC[A]): Array[Byte] = jwt.JWTPrinter.pretty(body.asJson).utf8Bytes

      def fromUtf8Bytes(array: Array[Byte]): Either[Error, JWSJOSEMAC[A]] =
        io.circe.parser.decode[JWSJOSEMAC[A]](array.toUtf8String)
    }

}
