package tsec.jwt

import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.{LinkedHashMap => LHM}

import cats.effect.Sync
import io.circe.Decoder.Result
import io.circe._
import io.circe.generic.auto._
import io.circe.parser.decode
import io.circe.syntax._
import tsec.common.{SecureRandomId, TSecError}
import tsec.jws.JWSSerializer

import scala.concurrent.duration.FiniteDuration
import scala.util.control.NonFatal

sealed abstract case class JWTClaims(
    issuer: Option[String] = None, //Case insensitive
    subject: Option[String] = None, //Case-sensitive
    audience: Option[Either[String, List[String]]] = None, //case-sensitive
    expiration: Option[Instant] = None, // IEEE Std 1003.1, 2013 Edition time in seconds
    notBefore: Option[Instant] = None, // IEEE Std 1003.1, 2013 Edition time in seconds
    issuedAt: Option[Instant], // IEEE Std 1003.1, 2013 Edition time in seconds
    jwtId: String = SecureRandomId.generate, //Case sensitive, and in our implementation, secure enough using UUIDv4
    private[tsec] val cachedCursor: HCursor
) { self =>

  private def copy(
      issuer: Option[String] = self.issuer,
      subject: Option[String] = self.subject,
      audience: Option[Either[String, List[String]]] = self.audience,
      expiration: Option[Instant] = self.expiration,
      notBefore: Option[Instant] = self.notBefore,
      issuedAt: Option[Instant] = self.issuedAt,
      jwtId: String = self.jwtId,
      c: HCursor
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
    cachedCursor.downField(key).as[A]

  def getCustomF[F[_], A: Decoder](key: String)(implicit F: Sync[F]): F[A] =
    F.fromEither(cachedCursor.downField(key).as[A])

  def withIssuer(isr: String): JWTClaims = {
    val modified =
      cachedCursor
        .downField(JWTClaims.Issuer)
        .withFocus(_ => Json.fromString(isr))

    copy(
      issuer = Some(isr),
      c = modified.top.get.hcursor //This is ok, since we can guarantee via construction that `Expiration` exists
    )
  }

  def withSubject(subj: String): JWTClaims = {
    val modified =
      cachedCursor
        .downField(JWTClaims.Subject)
        .withFocus(_ => Json.fromString(subj))

    copy(
      subject = Some(subj),
      c = modified.top.get.hcursor //This is ok, since we can guarantee via construction that `Expiration` exists
    )
  }

  def withExpiry(duration: Instant): JWTClaims = {
    val modified =
      cachedCursor
        .downField(JWTClaims.Expiration)
        .withFocus(_ => Json.fromLong(duration.getEpochSecond))

    copy(
      expiration = Some(duration),
      c = modified.top.get.hcursor //This is ok, since we can guarantee via construction that `Expiration` exists
    )
  }

  def withIAT(duration: Instant): JWTClaims = {
    val modified =
      cachedCursor
        .downField(JWTClaims.IssuedAt)
        .withFocus(_ => Json.fromLong(duration.getEpochSecond))

    copy(
      issuedAt = Some(duration),
      c = modified.top.get.hcursor //This is ok, since we can guarantee via construction that `iat` exists
    )
  }

  def withNBF(duration: Instant): JWTClaims = {
    val modified: ACursor =
      cachedCursor
        .downField(JWTClaims.NotBefore)
        .withFocus(_ => Json.fromLong(duration.getEpochSecond))

    copy(
      notBefore = Some(duration),
      c = modified.top.get.hcursor //This is ok, since we can guarantee via construction that `iat` exists
    )
  }

  def withJwtID(jwtId: String): JWTClaims = {
    val modified: ACursor =
      cachedCursor
        .downField(JWTClaims.JwtId)
        .withFocus(_ => Json.fromString(jwtId))

    copy(
      jwtId = jwtId,
      c = modified.top.get.hcursor //This is ok, since we can guarantee via construction that `iat` exists
    )
  }

  def isNotExpired(now: Instant): Boolean = expiration.forall(e => now.isBefore(e))
  def isAfterNBF(now: Instant): Boolean   = notBefore.forall(e => now.isAfter(e))
  def isValidIssued(now: Instant): Boolean =
    issuedAt.forall(e => !now.isBefore(e))

}

sealed abstract class JWTClaimsBuilder[F[_]](
    issuer: Option[String] = None, //Case insensitive
    subject: Option[String] = None, //Case-sensitive
    audience: Option[Either[String, List[String]]] = None, //case-sensitive
    expiration: Option[Instant] = None,
    notBefore: Option[Instant] = None,
    issuedAt: Option[Instant], // IEEE Std 1003.1, 2013 Edition time in seconds
    jwtId: String = SecureRandomId.generate, //Case sensitive, and in our implementation, secure enough using UUIDv4
    private[tsec] val claims: LHM[String, Json]
) {

  def withIssuer(isr: String)(implicit F: Sync[F]): F[JWTClaimsBuilder[F]] = F.delay {
    claims.put(JWTClaims.Issuer, Json.fromString(isr))
    this
  }

  def withSubject(sub: String)(implicit F: Sync[F]): F[JWTClaimsBuilder[F]] = F.delay {
    claims.put(JWTClaims.Subject, Json.fromString(sub))
    this
  }

  def withAudience(aud: Either[String, List[String]])(implicit F: Sync[F]): F[JWTClaimsBuilder[F]] = F.delay {
    claims.put(JWTClaims.Audience, aud.fold(_.asJson, _.asJson))
    this
  }

  def withIssuedAt(duration: FiniteDuration)(implicit F: Sync[F]): F[JWTClaimsBuilder[F]] =
    F.map(F.delay(Instant.now().getEpochSecond)) { now =>
      claims.put(JWTClaims.IssuedAt, Json.fromLong(now + duration.toSeconds))
      this
    }

  def withExpiry(expiry: FiniteDuration)(implicit F: Sync[F]): F[JWTClaimsBuilder[F]] =
    F.map(F.delay(Instant.now().getEpochSecond)) { now =>
      claims.put(JWTClaims.Expiration, Json.fromLong(now + expiry.toSeconds))
      this
    }

  def withNotBefore(notBefore: FiniteDuration)(implicit F: Sync[F]): F[JWTClaimsBuilder[F]] =
    F.map(F.delay(Instant.now().getEpochSecond)) { now =>
      claims.put(JWTClaims.NotBefore, Json.fromLong(now + notBefore.toSeconds))
      this
    }

  def withIssuedAt(instant: Instant)(implicit F: Sync[F]): F[JWTClaimsBuilder[F]] = F.delay {
    claims.put(JWTClaims.IssuedAt, Json.fromLong(instant.getEpochSecond))
    this
  }

  def withExpiry(expiry: Instant)(implicit F: Sync[F]): F[JWTClaimsBuilder[F]] = F.delay {
    claims.put(JWTClaims.Expiration, Json.fromLong(expiry.getEpochSecond))
    this
  }

  def withNotBefore(notBefore: Instant)(implicit F: Sync[F]): F[JWTClaimsBuilder[F]] = F.delay {
    claims.put(JWTClaims.NotBefore, Json.fromLong(notBefore.getEpochSecond))
    this
  }

  def withJWTId(id: String)(implicit F: Sync[F]): F[JWTClaimsBuilder[F]] = F.delay {
    claims.put(JWTClaims.JwtId, Json.fromString(id))
    this
  }

  def withField[A](name: String, value: A)(implicit F: Sync[F], encoder: Encoder[A]): F[JWTClaimsBuilder[F]] =
    F.delay {
      claims.putIfAbsent(name, encoder(value))
      this
    }

  def withFields(fields: (String, Json)*)(implicit F: Sync[F]): F[JWTClaimsBuilder[F]] = withFieldSeq(fields)

  def withFieldSeq(fields: Seq[(String, Json)])(implicit F: Sync[F]): F[JWTClaimsBuilder[F]] =
    F.delay {
      fields.foreach {
        case (k, v) => claims.putIfAbsent(k, v)
      }
      this
    }

  def unsafeWithField[A](name: String, value: A)(encoder: Encoder[A]): JWTClaimsBuilder[F] = {
    claims.putIfAbsent(name, encoder(value))
    this
  }

  def unsafeWithFields(fields: (String, Json)*): JWTClaimsBuilder[F] = unsafeWithFieldSeq(fields)

  def unsafeWithFieldSeq(fields: Seq[(String, Json)]): JWTClaimsBuilder[F] = {
    fields.foreach {
      case (k, v) => claims.putIfAbsent(k, v)
    }
    this
  }

  def build: JWTClaims = {
    val itr: Iterable[(String, Json)] = JWTClaims.lhmIterator[String, Json](claims)

    new JWTClaims(
      issuer,
      subject,
      audience,
      expiration,
      notBefore,
      issuedAt,
      jwtId,
      HCursor.fromJson(Json.fromFields(itr))
    ) {}
  }

}

object JWTClaimsBuilder {
  def apply[F[_]](
      issuer: Option[String] = None, //Case insensitive
      subject: Option[String] = None, //Case-sensitive
      audience: Option[Either[String, List[String]]] = None, //case-sensitive
      expiration: Option[Instant] = None,
      notBefore: Option[Instant] = None,
      issuedAt: Option[Instant] = None, // IEEE Std 1003.1, 2013 Edition time in seconds
      jwtId: String = SecureRandomId.generate //Case sensitive, and in our implementation, secure enough using UUIDv4
  ): JWTClaimsBuilder[F] = {
    val hashMap = new LHM[String, Json](JWTClaims.StandardClaims.length)
    hashMap.put(JWTClaims.Issuer, issuer.map(Json.fromString).getOrElse(Json.Null))
    hashMap.put(JWTClaims.Subject, subject.map(Json.fromString).getOrElse(Json.Null))
    hashMap.put(JWTClaims.Audience, audience.map(_.fold(_.asJson, _.asJson)).getOrElse(Json.Null))
    hashMap.put(JWTClaims.Expiration, expiration.map(e => Json.fromLong(e.getEpochSecond)).getOrElse(Json.Null))
    hashMap.put(JWTClaims.NotBefore, notBefore.map(e => Json.fromLong(e.getEpochSecond)).getOrElse(Json.Null))
    hashMap.put(JWTClaims.IssuedAt, issuedAt.map(e => Json.fromLong(e.getEpochSecond)).getOrElse(Json.Null))
    hashMap.put(JWTClaims.JwtId, Json.fromString(jwtId))

    new JWTClaimsBuilder[F](issuer, subject, audience, expiration, notBefore, issuedAt, jwtId, hashMap) {}
  }

}

object JWTClaims extends JWSSerializer[JWTClaims] {
  private[tsec] def lhmIterator[A, B](lhm: LHM[A, B]): Iterable[(A, B)] = new Iterable[(A, B)] {
    def iterator: Iterator[(A, B)] = new Iterator[(A, B)] {

      private[this] val underlying = lhm.entrySet.iterator

      final def hasNext: Boolean = underlying.hasNext

      final def next(): (A, B) = {
        val field = underlying.next()

        (field.getKey, field.getValue)
      }
    }
  }

  object InvalidFieldError extends TSecError {
    def cause: String = "Standard JWT Field Violation"
  }

  def apply(
      issuer: Option[String] = None,
      subject: Option[String] = None,
      audience: Option[Either[String, List[String]]] = None,
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
      audience: Option[Either[String, List[String]]] = None,
      expiration: Option[Instant] = None,
      notBefore: Option[Instant] = None, // IEEE Std 1003.1, 2013 Edition time in seconds
      issuedAt: Option[Instant] = None,
      jwtId: String = SecureRandomId.generate,
      customFields: Seq[(String, Json)] = Nil
  ): JWTClaims = {
    val hashMap = new LHM[String, Json](JWTClaims.StandardClaims.length)
    hashMap.put(JWTClaims.Issuer, issuer.map(Json.fromString).getOrElse(Json.Null))
    hashMap.put(JWTClaims.Subject, subject.map(Json.fromString).getOrElse(Json.Null))
    hashMap.put(JWTClaims.Audience, audience.map(_.fold(_.asJson, _.asJson)).getOrElse(Json.Null))
    hashMap.put(JWTClaims.Expiration, expiration.map(e => Json.fromLong(e.getEpochSecond)).getOrElse(Json.Null))
    hashMap.put(JWTClaims.NotBefore, notBefore.map(e => Json.fromLong(e.getEpochSecond)).getOrElse(Json.Null))
    hashMap.put(JWTClaims.IssuedAt, issuedAt.map(e => Json.fromLong(e.getEpochSecond)).getOrElse(Json.Null))
    hashMap.put(JWTClaims.JwtId, Json.fromString(jwtId))

    val cursor = HCursor.fromJson(Json.fromFields(JWTClaims.lhmIterator[String, Json](hashMap)))

    customFields.foreach {
      case (k, v) => hashMap.putIfAbsent(k, v)
    }

    new JWTClaims(
      issuer,
      subject,
      audience,
      expiration,
      notBefore,
      issuedAt,
      jwtId,
      cursor
    ) {}
  }

  def withDuration[F[_]](
      issuer: Option[String] = None,
      subject: Option[String] = None,
      audience: Option[Either[String, List[String]]] = None,
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
    hashMap.put(JWTClaims.Audience, audience.map(_.fold(_.asJson, _.asJson)).getOrElse(Json.Null))
    hashMap.put(JWTClaims.Expiration, exp.map(e => Json.fromLong(e.getEpochSecond)).getOrElse(Json.Null))
    hashMap.put(JWTClaims.NotBefore, nbf.map(e => Json.fromLong(e.getEpochSecond)).getOrElse(Json.Null))
    hashMap.put(JWTClaims.IssuedAt, iat.map(e => Json.fromLong(e.getEpochSecond)).getOrElse(Json.Null))
    hashMap.put(JWTClaims.JwtId, Json.fromString(jwtId))

    customFields.foreach {
      case (k, v) => hashMap.putIfAbsent(k, v)
    }

    val cursor = HCursor.fromJson(Json.fromFields(JWTClaims.lhmIterator[String, Json](hashMap)))

    new JWTClaims(
      issuer,
      subject,
      audience,
      exp,
      nbf,
      iat,
      jwtId,
      cursor
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
    def apply(a: JWTClaims): Json = a.cachedCursor.value
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
    def apply(c: HCursor): Result[JWTClaims] =
      for {
        iss        <- c.downField("iss").as[Option[String]]
        sub        <- c.downField("sub").as[Option[String]]
        aud        <- c.downField("aud").as[Option[Either[String, List[String]]]]
        expiration <- c.downField("exp").as[Option[Long]].flatMap(unsafeInstant)
        nbf        <- c.downField("nbf").as[Option[Long]].flatMap(unsafeInstant)
        iat        <- c.downField("iat").as[Option[Long]].flatMap(unsafeInstant)
        jwtid      <- c.downField("jti").as[String]
      } yield new JWTClaims(iss, sub, aud, expiration, nbf, iat, jwtid, c) {}
  }

  def serializeToUtf8(body: JWTClaims): Array[Byte] = JWTPrinter.pretty(body.asJson).getBytes(StandardCharsets.UTF_8)

  def fromUtf8Bytes(array: Array[Byte]): Either[Error, JWTClaims] =
    decode[JWTClaims](new String(array, StandardCharsets.UTF_8))
}
