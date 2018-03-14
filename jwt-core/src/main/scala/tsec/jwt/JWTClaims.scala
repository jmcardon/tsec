package tsec.jwt

import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.{LinkedHashMap => LHM}

import cats.effect.Sync
import cats.instances.string._
import io.circe.Decoder.Result
import io.circe._
import io.circe.parser.decode
import io.circe.syntax._
import tsec.common.{ByteUtils, SecureRandomId, TSecError}
import tsec.internal.CirceShim
import tsec.jws.JWSSerializer

import scala.concurrent.duration.FiniteDuration
import scala.util.control.NonFatal

/** Represents the JWT Claims in
  * https://tools.ietf.org/html/rfc7519#section-4
  *
  * Times are IEEE Std 1003.1, 2013 Edition time in seconds. They are represented
  * in a java.time.Instant objects. At serialization time, they are
  * represented as `Long`.
  *
  * Note: When feeding `Instant` instances directly, milliseconds are discarded
  *
  * @param issuer Issuer claim, Case insensitive
  * @param subject Subject, Case-sensitive string
  * @param audience The audience Case-sensitive. Can be either a list or a single string
  * @param expiration The token expiration time
  * @param notBefore identifies the time before which the JWT MUST NOT be accepted for processing.
  * @param issuedAt identifies the time at which the JWT was issued
  * @param jwtId provides a unique identifier for the JWT
  */
sealed abstract case class JWTClaims(
    issuer: Option[String],
    subject: Option[String],
    audience: Option[JWTAudience], //case-sensitive
    expiration: Option[Instant],
    notBefore: Option[Instant], // IEEE Std 1003.1, 2013 Edition time in seconds
    issuedAt: Option[Instant], // IEEE Std 1003.1, 2013 Edition time in seconds
    jwtId: String, //Case sensitive, and in our implementation, secure enough using UUIDv4
    private[tsec] val cachedObj: JsonObject
) { self =>

  private def copy(
      issuer: Option[String] = self.issuer,
      subject: Option[String] = self.subject,
      audience: Option[JWTAudience] = self.audience,
      expiration: Option[Instant] = self.expiration,
      notBefore: Option[Instant] = self.notBefore,
      issuedAt: Option[Instant] = self.issuedAt,
      jwtId: String = self.jwtId,
      c: JsonObject
  ): JWTClaims =
    new JWTClaims(
      issuer,
      subject,
      audience,
      expiration,
      notBefore,
      issuedAt,
      jwtId,
      c
    ) {}

  def getCustom[A: Decoder](key: String): Result[A] =
    cachedObj(key).map(_.as[A]).getOrElse(Left(DecodingFailure("No Such key", Nil)))

  def getCustomF[F[_], A: Decoder](key: String)(implicit F: Sync[F]): F[A] =
    cachedObj(key)
      .map(s => F.fromEither(s.as[A]))
      .getOrElse(F.raiseError(DecodingFailure("No Such key", Nil)))

  def withIssuer(isr: String): JWTClaims =
    copy(
      issuer = Some(isr),
      c = cachedObj.add(JWTClaims.Issuer, Json.fromString(isr))
    )

  def withSubject(subj: String): JWTClaims =
    copy(
      subject = Some(subj),
      c = cachedObj.add(JWTClaims.Subject, Json.fromString(subj))
    )

  def withCustomField[A](key: String, value: A)(implicit e: Encoder[A]): Either[JWTClaims.InvalidField, JWTClaims] =
    if (ByteUtils.contains[String](JWTClaims.StandardClaims, key))
      Left(JWTClaims.InvalidFieldError)
    else {
      Right(
        copy(
          c = cachedObj.add(key, e(value))
        )
      )
    }

  def withCustomFieldF[F[_], A](key: String, value: A)(implicit F: Sync[F], e: Encoder[A]): F[JWTClaims] =
    if (ByteUtils.contains[String](JWTClaims.StandardClaims, key))
      F.raiseError[JWTClaims](JWTClaims.InvalidFieldError)
    else {
      F.pure(
        copy(
          c = cachedObj.add(key, e(value))
        )
      )
    }

  def withExpiry(duration: Instant): JWTClaims =
    copy(
      expiration = Some(duration),
      c = cachedObj.add(JWTClaims.Expiration, Json.fromLong(duration.getEpochSecond))
    )

  def withIAT(duration: Instant): JWTClaims =
    copy(
      issuedAt = Some(duration),
      c = cachedObj.add(JWTClaims.IssuedAt, Json.fromLong(duration.getEpochSecond))
    )

  def withNBF(duration: Instant): JWTClaims =
    copy(
      notBefore = Some(duration),
      c = cachedObj.add(JWTClaims.NotBefore, Json.fromLong(duration.getEpochSecond))
    )

  def withJwtID(jwtId: String): JWTClaims =
    copy(
      jwtId = jwtId,
      c = cachedObj.add(JWTClaims.JwtId, Json.fromString(jwtId))
    )

  def isNotExpired(now: Instant): Boolean = expiration.forall(e => now.isBefore(e))
  def isAfterNBF(now: Instant): Boolean   = notBefore.forall(e => now.isAfter(e))
  def isValidIssued(now: Instant): Boolean =
    issuedAt.forall(e => !now.isBefore(e))

}

object JWTClaims extends JWSSerializer[JWTClaims] {

  object InvalidFieldError extends TSecError {
    def cause: String = "Standard JWT Field Violation"
  }

  type InvalidField = InvalidFieldError.type

  def apply(
      issuer: Option[String] = None,
      subject: Option[String] = None,
      audience: Option[JWTAudience] = None,
      expiration: Option[Instant] = None,
      notBefore: Option[Instant] = None, // IEEE Std 1003.1, 2013 Edition time in seconds
      issuedAt: Option[Instant] = None,
      jwtId: String = SecureRandomId.generate,
      customFields: Seq[(String, Json)] = Nil
  ): JWTClaims = default(
    issuer,
    subject,
    audience,
    expiration,
    notBefore,
    issuedAt,
    jwtId,
    customFields
  )

  def default(
      issuer: Option[String] = None,
      subject: Option[String] = None,
      audience: Option[JWTAudience] = None,
      expiration: Option[Instant] = None,
      notBefore: Option[Instant] = None,
      issuedAt: Option[Instant] = None,
      jwtId: String = SecureRandomId.generate,
      customFields: Seq[(String, Json)] = Nil
  ): JWTClaims = {
    val hashMap = new LHM[String, Json](JWTClaims.StandardClaims.length)
    hashMap.put(JWTClaims.Issuer, issuer.map(Json.fromString).getOrElse(Json.Null))
    hashMap.put(JWTClaims.Subject, subject.map(Json.fromString).getOrElse(Json.Null))
    hashMap.put(JWTClaims.Audience, audience.map(_.asJson).getOrElse(Json.Null))
    hashMap.put(JWTClaims.Expiration, expiration.map(e => Json.fromLong(e.getEpochSecond)).getOrElse(Json.Null))
    hashMap.put(JWTClaims.NotBefore, notBefore.map(e => Json.fromLong(e.getEpochSecond)).getOrElse(Json.Null))
    hashMap.put(JWTClaims.IssuedAt, issuedAt.map(e => Json.fromLong(e.getEpochSecond)).getOrElse(Json.Null))
    hashMap.put(JWTClaims.JwtId, Json.fromString(jwtId))

    customFields.foreach {
      case (k, v) => hashMap.putIfAbsent(k, v)
    }

    new JWTClaims(
      issuer,
      subject,
      audience,
      expiration.map(s => Instant.ofEpochSecond(s.getEpochSecond)),
      notBefore.map(s => Instant.ofEpochSecond(s.getEpochSecond)),
      issuedAt.map(s => Instant.ofEpochSecond(s.getEpochSecond)),
      jwtId,
      CirceShim.fromLinkedHashMap(hashMap)
    ) {}
  }

  def withDuration[F[_]](
      issuer: Option[String] = None,
      subject: Option[String] = None,
      audience: Option[JWTAudience] = None,
      expiration: Option[FiniteDuration] = None,
      notBefore: Option[FiniteDuration] = None, // IEEE Std 1003.1, 2013 Edition time in seconds
      issuedAt: Option[FiniteDuration] = None,
      jwtId: String = SecureRandomId.generate,
      customFields: Seq[(String, Json)] = Nil
  )(implicit F: Sync[F]): F[JWTClaims] = F.map(F.delay(Instant.now().getEpochSecond)) { now =>
    val exp = expiration.map(s => Instant.ofEpochSecond(s.toSeconds + now))
    val nbf = notBefore.map(s => Instant.ofEpochSecond(s.toSeconds + now))
    val iat = issuedAt.map(s => Instant.ofEpochSecond(s.toSeconds + now))

    val hashMap = new LHM[String, Json](JWTClaims.StandardClaims.length)
    hashMap.put(JWTClaims.Issuer, issuer.map(Json.fromString).getOrElse(Json.Null))
    hashMap.put(JWTClaims.Subject, subject.map(Json.fromString).getOrElse(Json.Null))
    hashMap.put(JWTClaims.Audience, audience.map(_.asJson).getOrElse(Json.Null))
    hashMap.put(JWTClaims.Expiration, exp.map(e => Json.fromLong(e.getEpochSecond)).getOrElse(Json.Null))
    hashMap.put(JWTClaims.NotBefore, nbf.map(e => Json.fromLong(e.getEpochSecond)).getOrElse(Json.Null))
    hashMap.put(JWTClaims.IssuedAt, iat.map(e => Json.fromLong(e.getEpochSecond)).getOrElse(Json.Null))
    hashMap.put(JWTClaims.JwtId, Json.fromString(jwtId))

    customFields.foreach {
      case (k, v) => hashMap.putIfAbsent(k, v)
    }

    new JWTClaims(
      issuer,
      subject,
      audience,
      exp,
      nbf,
      iat,
      jwtId,
      CirceShim.fromLinkedHashMap(hashMap)
    ) {}
  }

  /** Standard fields **/
  val Issuer: String     = "iss"
  val Subject: String    = "sub"
  val Audience: String   = "aud"
  val Expiration: String = "exp"
  val NotBefore: String  = "nbf"
  val IssuedAt: String   = "iat"
  val JwtId: String      = "jti"

  private[tsec] val StandardClaims: Array[String] =
    Array(Issuer, Subject, Audience, Expiration, NotBefore, IssuedAt, JwtId)

  implicit val encoder: Encoder[JWTClaims] = new Encoder[JWTClaims] {
    def apply(a: JWTClaims): Json = Json.fromJsonObject(a.cachedObj)
  }

  final private def unsafeInstant(i: Option[Long]): Decoder.Result[Option[Instant]] = i match {
    case None =>
      Right(None)
    case Some(ins) =>
      try {
        Right(Some(Instant.ofEpochSecond(ins)))
      } catch {
        case NonFatal(e) => Left(DecodingFailure("invalid date", Nil))
      }
  }

  implicit val claimsDecoder: Decoder[JWTClaims] = new Decoder[JWTClaims] {
    def apply(c: HCursor): Result[JWTClaims] = c.value.asObject match {
      case Some(obj) =>
        for {
          iss        <- c.downField(Issuer).as[Option[String]]
          sub        <- c.downField(Subject).as[Option[String]]
          aud        <- c.downField(Audience).as[Option[JWTAudience]]
          expiration <- c.downField(Expiration).as[Option[Long]].flatMap(unsafeInstant)
          nbf        <- c.downField(NotBefore).as[Option[Long]].flatMap(unsafeInstant)
          iat        <- c.downField(IssuedAt).as[Option[Long]].flatMap(unsafeInstant)
          jwtid      <- c.downField(JwtId).as[String]
        } yield new JWTClaims(iss, sub, aud, expiration, nbf, iat, jwtid, obj) {}

      case None =>
        Left(DecodingFailure("Invalid JSON", Nil))
    }

  }

  def serializeToUtf8(body: JWTClaims): Array[Byte] = JWTPrinter.pretty(body.asJson).getBytes(StandardCharsets.UTF_8)

  def fromUtf8Bytes(array: Array[Byte]): Either[Error, JWTClaims] =
    decode[JWTClaims](new String(array, StandardCharsets.UTF_8))

}
