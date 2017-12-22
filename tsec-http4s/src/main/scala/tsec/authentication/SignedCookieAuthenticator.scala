package tsec.authentication

import java.time.Instant
import java.util.UUID

import cats.MonadError
import cats.data.OptionT
import cats.effect.Sync
import io.circe.{Decoder, Encoder}
import org.http4s._
import tsec.cookies._
import tsec.mac.imports._
import tsec.messagedigests._
import tsec.messagedigests.imports._
import tsec.common._
import cats.syntax.all._
import tsec.mac.core.MacTag

import scala.concurrent.duration.FiniteDuration

abstract class SignedCookieAuthenticator[F[_]: Sync, I, V, Alg: MacTag] private[tsec] (
    val expiry: FiniteDuration,
    val maxIdle: Option[FiniteDuration]
) extends AuthenticatorService[F, I, V, AuthenticatedCookie[Alg, I]]

/** An authenticated cookie implementation
  *
  * @param id the cookie id
  * @param content the raw cookie: The full thing, including the nonce
  * @param identity The id of what
  * @tparam A Our Mac algorithm we are signing the cookie with.
  * @tparam Id
  */
final case class AuthenticatedCookie[A, Id](
    id: UUID,
    name: String,
    content: SignedCookie[A],
    identity: Id,
    expiry: Instant,
    lastTouched: Option[Instant],
    secure: Boolean,
    httpOnly: Boolean = true,
    domain: Option[String] = None,
    path: Option[String] = None,
    extension: Option[String] = None
) extends Authenticator[Id] {
  def toCookie = Cookie(
    name,
    content,
    Some(HttpDate.unsafeFromInstant(expiry)),
    None,
    domain,
    path,
    secure,
    httpOnly,
    extension
  )
}

object AuthenticatedCookie {
  def build[A, Id](
      id: UUID,
      content: SignedCookie[A],
      messageId: Id,
      expiry: Instant,
      lastTouched: Option[Instant],
      settings: TSecCookieSettings
  ): AuthenticatedCookie[A, Id] =
    AuthenticatedCookie[A, Id](
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
}

object SignedCookieAuthenticator {

  def apply[F[_], I: Decoder: Encoder, V, Alg: MacTag](
      settings: TSecCookieSettings,
      tokenStore: BackingStore[F, UUID, AuthenticatedCookie[Alg, I]],
      idStore: BackingStore[F, I, V],
      key: MacSigningKey[Alg]
  )(implicit F: Sync[F]): SignedCookieAuthenticator[F, I, V, Alg] =
    new SignedCookieAuthenticator[F, I, V, Alg](settings.expiryDuration, settings.maxIdle) {

      def withNewKey(newKey: MacSigningKey[Alg]): SignedCookieAuthenticator[F, I, V, Alg] =
        apply[F, I, V, Alg](
          settings: TSecCookieSettings,
          tokenStore: BackingStore[F, UUID, AuthenticatedCookie[Alg, I]],
          idStore: BackingStore[F, I, V],
          newKey
        )

      def withTokenStore(
          newStore: BackingStore[F, UUID, AuthenticatedCookie[Alg, I]]
      ): SignedCookieAuthenticator[F, I, V, Alg] =
        apply[F, I, V, Alg](
          settings: TSecCookieSettings,
          newStore: BackingStore[F, UUID, AuthenticatedCookie[Alg, I]],
          idStore: BackingStore[F, I, V],
          key
        )

      def withIdStore(newStore: BackingStore[F, I, V]): SignedCookieAuthenticator[F, I, V, Alg] =
        apply[F, I, V, Alg](
          settings: TSecCookieSettings,
          tokenStore: BackingStore[F, UUID, AuthenticatedCookie[Alg, I]],
          newStore,
          key
        )

      def withSettings(newSettings: TSecCookieSettings): SignedCookieAuthenticator[F, I, V, Alg] =
        apply[F, I, V, Alg](
          newSettings: TSecCookieSettings,
          tokenStore: BackingStore[F, UUID, AuthenticatedCookie[Alg, I]],
          idStore,
          key
        )

      /** Generate a nonce by concatenating the message to be sent with the current instant and hashing their result
        * Possibly this should be a variable argument, but for now SHA1 is enough, since the chance for collision is
        * abysmally low.
        */
      private def generateNonce(message: String) =
        (message + Instant.now.toEpochMilli).utf8Bytes.hash[SHA1].toB64UrlString

      /** Validate our cookie's contents, as well as the parameters retrieved for the cookie
        * @param internal The backing store cookie information.
        * @param raw The cookie that was pulled from a request
        * @param now The current time.
        * @return
        */
      private def validateCookie(
          internal: AuthenticatedCookie[Alg, I],
          raw: SignedCookie[Alg],
          now: Instant
      ): Boolean =
        internal.content === raw && !internal.isExpired(now) && !settings.maxIdle.exists(internal.isTimedOut(now, _))

      private def validateAndRefresh(
          internal: AuthenticatedCookie[Alg, I],
          raw: SignedCookie[Alg],
          now: Instant
      ): OptionT[F, AuthenticatedCookie[Alg, I]] =
        if (validateCookie(internal, raw, now)) OptionT.liftF(refresh(internal)) else OptionT.none

      def extractRawOption(request: Request[F]): Option[String] =
        unliftedCookieFromRequest[F](settings.cookieName, request).map(_.content)

      def parseRaw(raw: String, request: Request[F]): OptionT[F, SecuredRequest[F, V, AuthenticatedCookie[Alg, I]]] =
        for {
          now <- OptionT.liftF(F.delay(Instant.now()))
          coerced = SignedCookie[Alg](raw)
          contentRaw <- OptionT.liftF(F.fromEither(CookieSigner.verifyAndRetrieve[Alg](coerced, key)))
          tokenId    <- uuidFromRaw[F](contentRaw)
          authed     <- tokenStore.get(tokenId)
          refreshed  <- validateAndRefresh(authed, coerced, now)
          identity   <- idStore.get(authed.identity)
        } yield SecuredRequest(request, identity, refreshed)

      /** Create an authenticator from an identifier.
        *
        * @param body
        * @return
        */
      def create(body: I): F[AuthenticatedCookie[Alg, I]] =
        for {
          cookieId <- F.delay(UUID.randomUUID())
          messageBody = cookieId.toString
          now <- F.delay(Instant.now())
          expiry      = now.plusSeconds(settings.expiryDuration.toSeconds)
          lastTouched = settings.maxIdle.map(_ => now)
          signed <- F.fromEither(CookieSigner.sign[Alg](messageBody, generateNonce(messageBody), key))
          cookie <- F.pure(
            AuthenticatedCookie.build[Alg, I](cookieId, signed, body, expiry, lastTouched, settings)
          )
          _ <- tokenStore.put(cookie)
        } yield cookie

      def update(authenticator: AuthenticatedCookie[Alg, I]): F[AuthenticatedCookie[Alg, I]] =
        tokenStore.update(authenticator)

      def discard(authenticator: AuthenticatedCookie[Alg, I]): F[AuthenticatedCookie[Alg, I]] =
        tokenStore.delete(authenticator.id).map(_ => authenticator)

      /** Renew an authenticator: Reset it's expiry and whatnot.
        *
        * @param authenticator
        * @return
        */
      def renew(authenticator: AuthenticatedCookie[Alg, I]): F[AuthenticatedCookie[Alg, I]] =
        F.delay(Instant.now()).flatMap { now =>
          settings.maxIdle match {
            case Some(idleTime) =>
              val updated = authenticator.copy[Alg, I](
                lastTouched = Some(now),
                expiry = now.plusSeconds(settings.expiryDuration.toSeconds)
              )
              tokenStore.update(updated).map(_ => updated)
            case None =>
              val updated = authenticator.copy[Alg, I](
                expiry = now.plusSeconds(settings.expiryDuration.toSeconds)
              )
              tokenStore.update(updated).map(_ => updated)
          }
        }

      /** Refresh an authenticator: Primarily used for sliding window expiration
        *
        * @param authenticator
        * @return
        */
      def refresh(authenticator: AuthenticatedCookie[Alg, I]): F[AuthenticatedCookie[Alg, I]] =
        F.delay(Instant.now()).flatMap { now =>
          settings.maxIdle match {
            case Some(idleTime) =>
              val updated = authenticator.copy[Alg, I](
                lastTouched = Some(now)
              )
              tokenStore.update(updated).map(_ => updated)
            case None =>
              F.pure(authenticator)
          }
        }

      def embed(response: Response[F], authenticator: AuthenticatedCookie[Alg, I]): Response[F] =
        response.addCookie(authenticator.toCookie)

      /** Handles the embedding of the authenticator (if necessary) in the response,
        * and any other actions that should happen after a request related to authenticators
        *
        * @param response
        * @param authenticator
        * @return
        */
      def afterBlock(response: Response[F], authenticator: AuthenticatedCookie[Alg, I]): OptionT[F, Response[F]] =
        settings.maxIdle match {
          case Some(_) =>
            OptionT.pure[F](response.addCookie(authenticator.toCookie))
          case None =>
            OptionT.pure[F](response)
        }
    }
}
