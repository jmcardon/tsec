package tsec.auth

import java.time.Instant
import java.util.UUID

import cats.Monad
import cats.data.OptionT
import io.circe.{Decoder, Encoder}
import io.circe.parser.decode
import org.http4s.util.CaseInsensitiveString
import org.http4s._
import tsec.cipher.common.AAD
import tsec.common.ByteEV
import tsec.messagedigests._
import tsec.messagedigests.imports._
import tsec.common._
import tsec.cipher.symmetric.imports._
import tsec.cookies._
import scala.concurrent.duration.FiniteDuration
import io.circe.syntax._
import io.circe.generic.auto._
import cats.implicits._
import tsec.jwt.JWTPrinter

abstract class EncryptedCookieAuthenticator[F[_], A, I, V](implicit auth: AuthEncryptor[A])
    extends AuthenticatorEV[F, A, I, V] {
  type Authenticator[T] = AuthEncryptedCookie[T, I]
}

/** An authenticated cookie implementation
  *
  * @param id the cookie id
  * @param content the raw cookie: The full thing, including the nonce
  * @param messageId The id of what
  * @param expiry
  * @param lastTouched
  * @tparam A
  * @tparam Id
  */
final case class AuthEncryptedCookie[A, Id](
    id: UUID,
    name: String,
    content: AEADCookie[A],
    messageId: Id,
    expiry: HttpDate,
    lastTouched: Option[HttpDate],
    secure: Boolean,
    httpOnly: Boolean = true,
    domain: Option[String] = None,
    path: Option[String] = None,
    extension: Option[String] = None
) {
  def isExpired(now: Instant): Boolean = expiry.toInstant.isBefore(now)
  def isTimedout(now: Instant, timeOut: FiniteDuration): Boolean =
    lastTouched.forall(
      _.toInstant
        .plusSeconds(timeOut.toSeconds)
        .isAfter(now)
    )
  def toCookie = Cookie(
    name,
    content,
    Some(expiry),
    None,
    domain,
    path,
    secure,
    httpOnly,
    extension
  )
}

object AuthEncryptedCookie {

  final case class Internal[Id](id: UUID, messageId: Id, expiry: HttpDate, lastTouched: Option[HttpDate])

  def build[A, Id](
      id: UUID,
      content: AEADCookie[A],
      messageId: Id,
      expiry: HttpDate,
      lastTouched: Option[HttpDate],
      settings: TSecCookieSettings
  ): AuthEncryptedCookie[A, Id] =
    AuthEncryptedCookie[A, Id](
      id,
      settings.cookieName,
      content,
      messageId,
      expiry,
      lastTouched,
      settings.secure,
      settings.httpOnly,
      settings.domain,
      settings.path,
      settings.extension
    )

  def build[A, Id](
      internal: Internal[Id],
      content: AEADCookie[A],
      settings: TSecCookieSettings
  ) =
    AuthEncryptedCookie[A, Id](
      internal.id,
      settings.cookieName,
      content,
      internal.messageId,
      internal.expiry,
      internal.lastTouched,
      settings.secure,
      settings.httpOnly,
      settings.domain,
      settings.path,
      settings.extension
    )

}

object EncryptedCookieAuthenticator {

  def withBackingStore[F[_]: Monad, Alg: AuthEncryptor: ByteEV, I: Decoder: Encoder, V](
      settings: TSecCookieSettings,
      tokenStore: BackingStore[F, UUID, AuthEncryptedCookie[Alg, I]],
      idStore: BackingStore[F, I, V],
      key: SecretKey[Alg],
      expiryDuration: FiniteDuration,
      maxIdle: Option[FiniteDuration]
  ) =
    new EncryptedCookieAuthenticator[F, Alg, I, V] {

      private def generateAAD(message: String) =
        AAD((message + Instant.now.toEpochMilli).utf8Bytes.hash[SHA1])

      private def validateCookie(
          internal: AuthEncryptedCookie[Alg, I],
          raw: AEADCookie[Alg],
          now: Instant
      ): Boolean =
        internal.content === raw && !internal.isExpired(now) && !maxIdle.forall(internal.isTimedout(now, _))

      private def validateCookieT(
          internal: AuthEncryptedCookie[Alg, I],
          raw: AEADCookie[Alg],
          now: Instant
      ): OptionT[F, Unit] =
        if (validateCookie(internal, raw, now)) OptionT.pure[F](()) else OptionT.none

      def extractAndValidate(request: Request[F]): OptionT[F, SecuredRequest[F, AuthEncryptedCookie[Alg, I], V]] = {
        val now = Instant.now()
        for {
          rawCookie <- cookieFromRequest[F](settings.cookieName, request)
          coerced = AEADCookie.fromRaw[Alg](rawCookie.content)
          contentRaw <- OptionT.fromOption[F](AEADCookieEncryptor.retrieveFromSigned[Alg](coerced, key).toOption)
          tokenId    <- OptionT.fromOption[F](decode[UUID](contentRaw).toOption)
          authed     <- tokenStore.get(tokenId)
          _          <- validateCookieT(authed, coerced, now)
          refreshed  <- refresh(authed)
          identity   <- idStore.get(authed.messageId)
        } yield SecuredRequest(request, refreshed, identity)
      }

      def create(body: I): OptionT[F, AuthEncryptedCookie[Alg, I]] = {
        val cookieId    = UUID.randomUUID()
        val now         = Instant.now()
        val expiry      = HttpDate.unsafeFromInstant(now.plusSeconds(expiryDuration.toSeconds))
        val lastTouched = maxIdle.map(_ => HttpDate.unsafeFromInstant(now))
        val messageBody = cookieId.toString
        for {
          encrypted <- OptionT.fromOption[F](
            AEADCookieEncryptor.signAndEncrypt[Alg](messageBody, generateAAD(messageBody), key).toOption
          )
          cookie <- OptionT.pure[F](
            AuthEncryptedCookie.build[Alg, I](cookieId, encrypted, body, expiry, lastTouched, settings)
          )
          _ <- OptionT.liftF(tokenStore.put(cookie))
        } yield cookie
      }

      def renew(authenticator: AuthEncryptedCookie[Alg, I]): OptionT[F, AuthEncryptedCookie[Alg, I]] = maxIdle match {
        case Some(idleTime) =>
          val now = Instant.now()
          val updated = authenticator.copy[Alg, I](
            lastTouched = Some(HttpDate.unsafeFromInstant(now.plusSeconds(idleTime.toSeconds))),
            expiry = HttpDate.unsafeFromInstant(now.plusSeconds(expiryDuration.toSeconds))
          )
          OptionT.liftF(tokenStore.update(updated)).map(_ => updated)
        case None =>
          OptionT.pure[F](authenticator)
      }

      def refresh(authenticator: AuthEncryptedCookie[Alg, I]): OptionT[F, AuthEncryptedCookie[Alg, I]] = maxIdle match {
        case Some(idleTime) =>
          val now = Instant.now()
          val updated = authenticator.copy[Alg, I](
            lastTouched = Some(HttpDate.unsafeFromInstant(now.plusSeconds(idleTime.toSeconds)))
          )
          OptionT.liftF(tokenStore.update(updated)).map(_ => updated)
        case None =>
          OptionT.pure[F](authenticator)
      }

      def embed(response: Response[F], authenticator: AuthEncryptedCookie[Alg, I]): Response[F] =
        response.addCookie(authenticator.toCookie)

      def afterBlock(response: Response[F], authenticator: AuthEncryptedCookie[Alg, I]): OptionT[F, Response[F]] =
        maxIdle match {
          case Some(_) =>
            OptionT.pure[F](response.addCookie(authenticator.toCookie))
          case None =>
            OptionT.pure[F](response)
        }
    }

  /**
    * Generate a stateless cookie authenticator that stores the authentication data in the backing store.
    * Since we have no way to verify that the cookie's expiration and sliding window haven't been modified,
    * we encrypt it as part of the contents
    *
    * @param settings
    * @param idStore
    * @param key
    * @param expiryDuration
    * @param maxIdle
    * @tparam F
    * @tparam Alg
    * @tparam I
    * @tparam V
    * @return
    */
  def stateless[F[_]: Monad, Alg: AuthEncryptor: ByteEV, I: Decoder: Encoder, V](
      settings: TSecCookieSettings,
      idStore: BackingStore[F, I, V],
      key: SecretKey[Alg],
      expiryDuration: FiniteDuration,
      maxIdle: Option[FiniteDuration]
  ) =
    new EncryptedCookieAuthenticator[F, Alg, I, V] {
      private val cookieName = CaseInsensitiveString(settings.cookieName)

      private def generateAAD(message: String) =
        AAD((message + Instant.now.toEpochMilli).utf8Bytes.hash[SHA1])

      private def validateCookie(
          internal: AuthEncryptedCookie[Alg, I],
          raw: AEADCookie[Alg],
          now: Instant
      ): Boolean =
        internal.content === raw && !internal.isExpired(now) && !maxIdle.forall(internal.isTimedout(now, _))

      private def validateCookieT(
          internal: AuthEncryptedCookie[Alg, I],
          raw: AEADCookie[Alg],
          now: Instant
      ): OptionT[F, Unit] =
        if (validateCookie(internal, raw, now)) OptionT.pure[F](()) else OptionT.none

      def extractAndValidate(request: Request[F]): OptionT[F, SecuredRequest[F, AuthEncryptedCookie[Alg, I], V]] = {
        val now = Instant.now()
        for {
          rawCookie <- cookieFromRequest[F](settings.cookieName, request)
          coerced = AEADCookie.fromRaw[Alg](rawCookie.content)
          contentRaw <- OptionT.fromOption[F](AEADCookieEncryptor.retrieveFromSigned[Alg](coerced, key).toOption)
          internal   <- OptionT.fromOption[F](decode[AuthEncryptedCookie.Internal[I]](contentRaw).toOption)
          authed = AuthEncryptedCookie.build[Alg, I](internal, coerced, TSecCookieSettings.fromCookie(rawCookie))
          _         <- validateCookieT(authed, coerced, now)
          refreshed <- refresh(authed)
          identity  <- idStore.get(authed.messageId)
        } yield SecuredRequest(request, refreshed, identity)
      }

      def create(body: I): OptionT[F, AuthEncryptedCookie[Alg, I]] = {
        val cookieId    = UUID.randomUUID()
        val now         = Instant.now()
        val expiry      = HttpDate.unsafeFromInstant(now.plusSeconds(expiryDuration.toSeconds))
        val lastTouched = maxIdle.map(_ => HttpDate.unsafeFromInstant(now))
        val messageBody = AuthEncryptedCookie.Internal(cookieId, body, expiry, lastTouched).asJson.pretty(JWTPrinter)
        for {
          encrypted <- OptionT.fromOption[F](
            AEADCookieEncryptor.signAndEncrypt[Alg](messageBody, generateAAD(messageBody), key).toOption
          )
          cookie <- OptionT.pure[F](
            AuthEncryptedCookie.build[Alg, I](cookieId, encrypted, body, expiry, lastTouched, settings)
          )
        } yield cookie
      }

      def renew(authenticator: AuthEncryptedCookie[Alg, I]): OptionT[F, AuthEncryptedCookie[Alg, I]] = maxIdle match {
        case Some(idleTime) =>
          val now = Instant.now()
          OptionT.pure[F](
            authenticator.copy[Alg, I](
              lastTouched = Some(HttpDate.unsafeFromInstant(now.plusSeconds(idleTime.toSeconds))),
              expiry = HttpDate.unsafeFromInstant(now.plusSeconds(expiryDuration.toSeconds))
            )
          )
        case None =>
          OptionT.pure[F](authenticator)
      }

      def refresh(authenticator: AuthEncryptedCookie[Alg, I]): OptionT[F, AuthEncryptedCookie[Alg, I]] = maxIdle match {
        case Some(idleTime) =>
          val now = Instant.now()
          OptionT.pure[F](
            authenticator.copy[Alg, I](
              lastTouched = Some(HttpDate.unsafeFromInstant(now.plusSeconds(idleTime.toSeconds)))
            )
          )
        case None =>
          OptionT.pure[F](authenticator)
      }

      def embed(response: Response[F], authenticator: AuthEncryptedCookie[Alg, I]): Response[F] =
        response.addCookie(authenticator.toCookie)

      def afterBlock(response: Response[F], authenticator: AuthEncryptedCookie[Alg, I]): OptionT[F, Response[F]] =
        maxIdle match {
          case Some(_) =>
            OptionT.pure[F](response.addCookie(authenticator.toCookie))
          case None =>
            OptionT.pure[F](response)
        }
    }
}
