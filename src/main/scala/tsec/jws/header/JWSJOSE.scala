package tsec.jws.header

import cats.data.NonEmptyList
import io.circe.syntax._
import io.circe.{Decoder, DecodingFailure, Encoder, Error, HCursor, Json}
import tsec.jws.{JWSSerializer, _}
import tsec.jws.algorithms.{JWA, JWTMacAlgo, JWTSigAlgo}
import tsec.jwt
import tsec.jwt.header.JWTHeader
import tsec.mac.MacKey
import tsec.mac.core.MacSigningKey
import tsec.mac.instance.MacTag
import tsec.signature.core.SigAlgoTag

sealed trait JWSJOSE[A] extends JWTHeader {
  def algorithm: JWA[A]
}

sealed abstract case class JWSJOSEMAC[A: MacTag](
    `type`: Option[String] = Some("JWT"), //Type, which will almost always default to "JWT"
    algorithm: JWTMacAlgo[A], //Algorithm, in this case a MAC
    contentType: Option[String] = None, // Optional header, preferably not used
    critical: Option[NonEmptyList[String]] = None //Headers not to ignore, they must be understood by the JWT implementation
) extends JWSJOSE[A]

object JWSJOSEMAC {
  type MK[A] = MacSigningKey[MacKey[A]]

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

  implicit def genSerializer[A: MacTag](
      implicit d: Decoder[JWSJOSEMAC[A]],
      e: Encoder[JWSJOSEMAC[A]]
  ): JWSSerializer[JWSJOSEMAC[A]] =
    new JWSSerializer[JWSJOSEMAC[A]] {
      def serializeToUtf8(body: JWSJOSEMAC[A]): Array[Byte] = jwt.JWTPrinter.pretty(body.asJson).utf8Bytes

      def fromUtf8Bytes(array: Array[Byte]): Either[Error, JWSJOSEMAC[A]] =
        io.circe.parser.decode[JWSJOSEMAC[A]](array.toUtf8String)
    }
}

sealed abstract case class JWSJOSESig[A: SigAlgoTag](
    `type`: Option[String] = Some("JWT"), //Type, which will almost always default to "JWT"
    algorithm: JWTSigAlgo[A], //Algorithm, in this case a MAC
    contentType: Option[String] = None, // Optional header, preferably not used
    critical: Option[NonEmptyList[String]] = None, //Headers not to ignore, they must be understood by the JWT implementation
    jku: Option[String] = None, //Resource set for JWK
    jwk: Option[String] = None, //JWK, eventually not a string,
    kid: Option[String] = None, //JWK key hint
    x5u: Option[String] = None, //The "x5c" (X.509 certificate chain) Header Parameter
    x5t: Option[String] = None,
    `x5t#S256`: Option[String] = None
) extends JWSJOSE[A]

object JWSJOSESig {
  implicit def encoder[A: SigAlgoTag] = new Encoder[JWSJOSESig[A]] {
    def apply(a: JWSJOSESig[A]): Json = Json.obj(
      ("typ", a.`type`.asJson),
      ("alg", a.algorithm.jwtRepr.asJson),
      ("cty", a.contentType.asJson),
      ("crit", a.critical.asJson),
      ("jku", a.jku.asJson),
      ("jwk", a.jwk.asJson),
      ("kid", a.kid.asJson),
      ("x5u", a.x5u.asJson),
      ("x5t#s256", a.`x5t#S256`.asJson)
    )
  }

  implicit def decoder[A: SigAlgoTag: JWTSigAlgo]: Decoder[JWSJOSESig[A]] = new Decoder[JWSJOSESig[A]] {
    def apply(c: HCursor): Either[DecodingFailure, JWSJOSESig[A]] =
      c.downField("alg")
        .as[Option[String]]
        .map(f => JWTSigAlgo.fromString[A](f.getOrElse(""))) match {
        case Right(opt) =>
          opt match {
            case Some(o) =>
              for {
                t      <- c.downField("typ").as[Option[String]]
                cType  <- c.downField("cty").as[Option[String]]
                crit   <- c.downField("crit").as[Option[NonEmptyList[String]]]
                jku    <- c.downField("jku").as[Option[String]]
                jwk    <- c.downField("jwk").as[Option[String]]
                kid    <- c.downField("kid").as[Option[String]]
                x5u    <- c.downField("x5u").as[Option[String]]
                x5t256 <- c.downField("x5t#s256").as[Option[String]]
              } yield
                new JWSJOSESig[A](
                  `type` = t,
                  algorithm = o,
                  contentType = cType,
                  critical = crit,
                  jku = jku,
                  jwk = jwk,
                  kid = kid,
                  x5u = x5u,
                  `x5t#S256` = x5t256
                ) {}
            case None =>
              Left(DecodingFailure("No algorithm found", Nil))
          }
        case Left(d) => Left(d)
      }
  }

  def genDeserializer[A: SigAlgoTag](
      implicit encoder: Encoder[JWSJOSESig[A]],
      decoder: Decoder[JWSJOSESig[A]]
  ): JWSSerializer[JWSJOSESig[A]] = new JWSSerializer[JWSJOSESig[A]] {
    def fromUtf8Bytes(array: Array[Byte]): Either[Error, JWSJOSESig[A]] =
      io.circe.parser.decode[JWSJOSESig[A]](array.toUtf8String)

    def serializeToUtf8(body: JWSJOSESig[A]): Array[Byte] = jwt.JWTPrinter.pretty(body.asJson).utf8Bytes
  }

}
