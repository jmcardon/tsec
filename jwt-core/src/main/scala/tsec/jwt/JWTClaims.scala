package tsec.jwt

import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.UUID

import io.circe.Decoder.Result
import io.circe._
import io.circe.generic.auto._
import io.circe.parser.decode
import io.circe.syntax._
import tsec.jws.JWSSerializer

import scala.concurrent.duration.FiniteDuration

case class JWTClaims(
    issuer: Option[String] = None, //Case insensitive
    subject: Option[String] = None, //Case-sensitive
    audience: Option[Either[String, List[String]]] = None, //case-sensitive
    expiration: Option[Long] = None,
    notBefore: Option[Long] = None,
    issuedAt: Option[Long] = Some(Instant.now().getEpochSecond), // IEEE Std 1003.1, 2013 Edition time in seconds
    jwtId: UUID = UUID.randomUUID(), //Case sensitive, and in our implementation, secure enough using UUIDv4
    custom: Option[Json] = None // non standard. I copped out. Other things are most likely too inefficient to use
) {
  def withExpiry(duration: FiniteDuration): JWTClaims =
    copy(expiration = Some(Instant.now.getEpochSecond + duration.toSeconds))
  def withIAT(duration: FiniteDuration): JWTClaims =
    copy(issuedAt = Some(Instant.now.getEpochSecond + duration.toSeconds))
  def withNBF(duration: FiniteDuration): JWTClaims =
    copy(notBefore = Some(Instant.now.getEpochSecond + duration.toSeconds))
  def isNotExpired(now: Instant): Boolean  = expiration.forall(e => now.isBefore(Instant.ofEpochSecond(e)))
  def isExpired(now: Instant): Boolean     = expiration.exists(e => now.isAfter(Instant.ofEpochSecond(e)))
  def isAfterNBF(now: Instant): Boolean    = notBefore.forall(e => now.isAfter(Instant.ofEpochSecond(e)))
  def isValidIssued(now: Instant): Boolean = issuedAt.forall(e => now.isAfter(Instant.ofEpochSecond(e)))

}

object JWTClaims extends JWSSerializer[JWTClaims] {

  def build(
      issuer: Option[String] = None, //Case insensitive
      subject: Option[String] = None, //Case-sensitive
      audience: Option[Either[String, List[String]]] = None, //case-sensitive
      expiration: Option[FiniteDuration],
      notBefore: Option[FiniteDuration] = None,
      jwtId: UUID = UUID.randomUUID(), //Case sensitive
      custom: Option[Json] = None
  ): JWTClaims = {
    val now = Instant.now().getEpochSecond
    val iat = Some(now)
    JWTClaims(
      issuer,
      subject,
      audience,
      expiration.map(_.toSeconds + now),
      notBefore.map(_.toSeconds + now),
      iat,
      jwtId,
      custom
    )
  }

  implicit val encoder: Encoder[JWTClaims] = new Encoder[JWTClaims] {
    def apply(a: JWTClaims): Json = Json.obj(
      ("iss", a.issuer.asJson),
      ("sub", a.subject.asJson),
      (
        "aud",
        a.audience
          .map {
            case Left(s)  => s.asJson
            case Right(b) => b.asJson
          }
          .getOrElse(Json.Null)
      ),
      ("exp", a.expiration.asJson),
      ("nbf", a.notBefore.asJson),
      ("iat", a.issuedAt.asJson),
      ("jti", a.jwtId.asJson),
      ("custom", a.custom.asJson)
    )
  }

  implicit val claimsDecoder: Decoder[JWTClaims] = new Decoder[JWTClaims] {
    def apply(c: HCursor): Result[JWTClaims] =
      for {
        iss        <- c.downField("iss").as[Option[String]]
        sub        <- c.downField("sub").as[Option[String]]
        aud        <- c.downField("aud").as[Option[Either[String, List[String]]]]
        expiration <- c.downField("exp").as[Option[Long]]
        nbf        <- c.downField("nbf").as[Option[Long]]
        iat        <- c.downField("iat").as[Option[Long]]
        jwtid      <- c.downField("jti").as[UUID]
        custom = c.downField("custom").focus
      } yield JWTClaims(iss, sub, aud, expiration, nbf, iat, jwtid, custom)
  }

  def serializeToUtf8(body: JWTClaims): Array[Byte] = JWTPrinter.pretty(body.asJson).getBytes(StandardCharsets.UTF_8)

  def fromUtf8Bytes(array: Array[Byte]): Either[Error, JWTClaims] =
    decode[JWTClaims](new String(array, StandardCharsets.UTF_8))
}
