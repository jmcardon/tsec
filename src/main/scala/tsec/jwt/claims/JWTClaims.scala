package tsec.jwt.claims

import java.nio.charset.StandardCharsets

import tsec.jwt._
import io.circe.{Encoder, Error, Json}
import io.circe.syntax._
import io.circe.parser.decode
import io.circe.generic.auto._
import tsec.jws.body.JWSSerializer

case class JWTClaims(
  issuer: Option[String] = None, //Case insensitive
  subject: Option[String] = None, //Case-sensitive
  audience: Option[Either[String, List[String]]] = None, //
  expiration: Option[Long] = None,
  notBefore: Option[Long] = None,
  issuedAt: Option[Long] = None,
  jwtId: Option[String] = None
)

object JWTClaims {
  implicit val encoder: Encoder[JWTClaims] = new Encoder[JWTClaims]{
    def apply(a: JWTClaims): Json = Json.obj(
      ("iss",a.issuer.asJson),
      ("sub", a.subject.asJson),
      ("aud", a.audience.map {
        case Left(s) => s.asJson
        case Right(b) => b.asJson
      }.getOrElse(Json.Null)),
      ("exp", a.expiration.asJson),
      ("nbf", a.notBefore.asJson),
      ("iat", a.issuedAt.asJson),
      ("jti", a.jwtId.asJson)
    )
  }

  implicit val jwsSerializer = new JWSSerializer[JWTClaims] {
    def serializeUtf8(body: JWTClaims): Array[Byte] = JWTPrinter.pretty(this.asJson).getBytes(StandardCharsets.UTF_8)
    def fromUtf8Bytes(array: Array[Byte]): Either[Error, JWTClaims] = decode[JWTClaims](new String(array, StandardCharsets.UTF_8))
  }
}