package tsec.jws.signature

import cats.data.NonEmptyList
import io.circe._
import io.circe.syntax._
import tsec.jwt
import tsec.jws._
import tsec.jwt.algorithms._
import tsec.jwt.header._
import tsec.common.ByteUtils._
import tsec.jws.header.JWSHeader
import tsec.messagedigests.imports.{SHA1, SHA256}

case class JWSSignedHeader[A](
    `type`: Option[JWTtyp] = Some(JWTtyp), //Type, which will almost always default to "JWT"
    contentType: Option[String] = None, // Optional header, preferably not used
    critical: Option[NonEmptyList[String]] = None, //Headers not to ignore, they must be understood by the JWT implementation
    jku: Option[String] = None, //Resource set for JWK
    jwk: Option[String] = None, //JWK
    kid: Option[String] = None, //JWK key hint
    x5u: Option[String] = None, //The "x5c" (X.509 certificate chain) Header Parameter
    x5t: Option[SHA1] = None, //sha1 hash
    `x5t#S256`: Option[SHA256] = None //sha256 hash
)(implicit val algorithm: JWTSigAlgo[A])
    extends JWSHeader[A]

object JWSSignedHeader {
  implicit def encoder[A: JWTSigAlgo]: Encoder[JWSSignedHeader[A]] = new Encoder[JWSSignedHeader[A]] {
    def apply(a: JWSSignedHeader[A]): Json = Json.obj(
      ("typ", a.`type`.asJson),
      ("alg", a.algorithm.jwtRepr.asJson),
      ("cty", a.contentType.asJson),
      ("crit", a.critical.asJson),
      ("jku", a.jku.asJson),
      ("jwk", a.jwk.asJson),
      ("kid", a.kid.asJson),
      ("x5u", a.x5u.asJson),
      ("x5t", a.x5t.map(_.array.toB64String).asJson),
      ("x5t#s256", a.`x5t#S256`.map(_.array.toB64String).asJson)
    )
  }

  implicit def decoder[A: JWTSigAlgo]: Decoder[JWSSignedHeader[A]] = new Decoder[JWSSignedHeader[A]] {
    def apply(c: HCursor): Either[DecodingFailure, JWSSignedHeader[A]] =
      c.downField("alg")
        .as[Option[String]]
        .map(f => JWTSigAlgo.fromString[A](f.getOrElse(""))) match {
        case Right(opt) =>
          opt match {
            case Some(_) =>
              for {
                t      <- c.downField("typ").as[Option[JWTtyp]]
                cType  <- c.downField("cty").as[Option[String]]
                crit   <- c.downField("crit").as[Option[NonEmptyList[String]]]
                jku    <- c.downField("jku").as[Option[String]]
                jwk    <- c.downField("jwk").as[Option[String]]
                kid    <- c.downField("kid").as[Option[String]]
                x5u    <- c.downField("x5u").as[Option[String]]
                x5t    <- c.downField("x5t").as[Option[String]]
                x5t256 <- c.downField("x5t#s256").as[Option[String]]
              } yield
                new JWSSignedHeader[A](
                  `type` = t,
                  contentType = cType,
                  critical = crit,
                  jku = jku,
                  jwk = jwk,
                  kid = kid,
                  x5u = x5u,
                  x5t = x5t.map(h => SHA1(h.base64Bytes)),
                  `x5t#S256` = x5t256.map(h => SHA256(h.base64Bytes))
                ) {}
            case None =>
              Left(DecodingFailure("No algorithm found", Nil))
          }
        case Left(d) => Left(d)
      }
  }

  implicit def genDeserializer[A: JWTSigAlgo](
      implicit encoder: Encoder[JWSSignedHeader[A]],
      decoder: Decoder[JWSSignedHeader[A]]
  ): JWSSerializer[JWSSignedHeader[A]] = new JWSSerializer[JWSSignedHeader[A]] {
    def fromUtf8Bytes(array: Array[Byte]): Either[Error, JWSSignedHeader[A]] =
      io.circe.parser.decode[JWSSignedHeader[A]](array.toUtf8String)

    def serializeToUtf8(body: JWSSignedHeader[A]): Array[Byte] = jwt.JWTPrinter.pretty(body.asJson).utf8Bytes
  }

}
