package tsec.authentication

import java.time.Instant
import java.util.UUID

import cats.data.OptionT
import cats.effect.Sync
import cats.syntax.all._
import org.http4s._
import tsec.common._
import tsec.cookies._
import tsec.hashing.jca._
import tsec.mac.MessageAuth
import tsec.mac.jca._

import scala.concurrent.duration.FiniteDuration

abstract class SignedCookieAuthenticator[F[_], I, V, Alg] private[tsec] (
    val tokenStore: BackingStore[F, UUID, AuthenticatedCookie[Alg, I]],
    val idStore: IdentityStore[F, I, V],
    val settings: TSecCookieSettings
)(implicit F: Sync[F])
    extends Authenticator[F, I, V, AuthenticatedCookie[Alg, I]] {

  val expiry: FiniteDuration = settings.expiryDuration

  val maxIdle: Option[FiniteDuration] = settings.maxIdle

  /** Generate a nonce by concatenating the message to be sent with the current instant and hashing their result
    * Possibly this should be a variable argument, but for now SHA1 is enough, since the chance for collision is
    * abysmally low.
    */
  private def generateNonce(message: String) =
    (message + Instant.now.toEpochMilli).utf8Bytes.hash[SHA1].toB64UrlString

  private[tsec] def validateCookie(
      internal: AuthenticatedCookie[Alg, I],
      raw: SignedCookie[Alg],
      now: Instant
  ): Boolean

  private[tsec] def verifyAndRetrieve(signed: SignedCookie[Alg]): F[String]

  private[tsec] def sign(message: String, nonce: String): F[SignedCookie[Alg]]

  /** Validate our cookie's contents, as well as the parameters retrieved for the cookie
    * @param internal The backing store cookie information.
    * @param raw The cookie that was pulled from a request
    * @param now The current time.
    * @return
    */
  private def validateAndRefresh(
      internal: AuthenticatedCookie[Alg, I],
      raw: SignedCookie[Alg],
      now: Instant
  ): OptionT[F, AuthenticatedCookie[Alg, I]] =
    if (validateCookie(internal, raw, now)) OptionT.liftF(refresh(internal)) else OptionT.none

  def extractRawOption(request: Request[F]): Option[String] =
    unliftedCookieFromRequest[F](settings.cookieName, request).map(_.content)

  def parseRaw(raw: String, request: Request[F]): OptionT[F, SecuredRequest[F, V, AuthenticatedCookie[Alg, I]]] =
    (for {
      now <- OptionT.liftF(F.delay(Instant.now()))
      coerced = SignedCookie[Alg](raw)
      contentRaw <- OptionT.liftF(verifyAndRetrieve(coerced))
      tokenId    <- uuidFromRaw[F](contentRaw)
      authed     <- tokenStore.get(tokenId)
      refreshed  <- validateAndRefresh(authed, coerced, now)
      identity   <- idStore.get(authed.identity)
    } yield SecuredRequest(request, identity, refreshed))
      .handleErrorWith(_ => OptionT.none)

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
      newExpiry   = now.plusSeconds(settings.expiryDuration.toSeconds)
      lastTouched = touch(now)
      signed <- sign(messageBody, generateNonce(messageBody))
      cookie <- F.pure(
        AuthenticatedCookie.build[Alg, I](cookieId, signed, body, newExpiry, lastTouched, settings)
      )
      _ <- tokenStore.put(cookie)
    } yield cookie

  def update(authenticator: AuthenticatedCookie[Alg, I]): F[AuthenticatedCookie[Alg, I]] =
    tokenStore.update(authenticator)

  def discard(authenticator: AuthenticatedCookie[Alg, I]): F[AuthenticatedCookie[Alg, I]] =
    tokenStore
      .delete(authenticator.id)
      .map(_ => authenticator.copy(content = SignedCookie[Alg]("invalid"), expiry = Instant.EPOCH))

  /** Renew an authenticator: Reset it's expiry and whatnot.
    *
    * @param authenticator
    * @return
    */
  def renew(authenticator: AuthenticatedCookie[Alg, I]): F[AuthenticatedCookie[Alg, I]] =
    F.delay(Instant.now()).flatMap { now =>
      val updated = authenticator.copy[Alg, I](
        lastTouched = touch(now),
        expiry = now.plusSeconds(settings.expiryDuration.toSeconds)
      )
      tokenStore.update(updated).map(_ => updated)
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
    OptionT.pure(response)
}

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
) {
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
  implicit def auth[A, Id]: AuthToken[AuthenticatedCookie[A, Id]] =
    new AuthToken[AuthenticatedCookie[A, Id]] {
      def expiry(a: AuthenticatedCookie[A, Id]): Instant = a.expiry

      def lastTouched(a: AuthenticatedCookie[A, Id]): Option[Instant] = a.lastTouched
    }

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

  private[tsec] def isExpired[I, Alg](
      internal: AuthenticatedCookie[Alg, I],
      now: Instant,
      maxIdle: Option[FiniteDuration]
  ): Boolean =
    !internal.isExpired(now) && !maxIdle.exists(internal.isTimedOut(now, _))

  private[tsec] def validateCookie[I, Alg](
      internal: AuthenticatedCookie[Alg, I],
      raw: SignedCookie[Alg],
      now: Instant,
      maxIdle: Option[FiniteDuration]
  ): Boolean =
    internal.content === raw && isExpired[I, Alg](internal, now, maxIdle)

  def apply[F[_], I, V, Alg](
      settings: TSecCookieSettings,
      tokenStore: BackingStore[F, UUID, AuthenticatedCookie[Alg, I]],
      idStore: IdentityStore[F, I, V],
      key: MacSigningKey[Alg]
  )(implicit F: Sync[F], S: MessageAuth[F, Alg, MacSigningKey]): SignedCookieAuthenticator[F, I, V, Alg] =
    settings.maxIdle match {
      case Some(mIdle) =>
        new SignedCookieAuthenticator[F, I, V, Alg](tokenStore, idStore, settings) {

          private[tsec] def validateCookie(
              internal: AuthenticatedCookie[Alg, I],
              raw: SignedCookie[Alg],
              now: Instant
          ): Boolean = raw === internal.content && !internal.isExpired(now) && !internal.isTimedOut(now, mIdle)

          private[tsec] def verifyAndRetrieve(signed: SignedCookie[Alg]): F[String] =
            CookieSigner.verifyAndRetrieve[F, Alg](signed, key)

          private[tsec] def sign(message: String, nonce: String): F[SignedCookie[Alg]] =
            CookieSigner.sign[F, Alg](message, nonce, key)

          def refresh(authenticator: AuthenticatedCookie[Alg, I]): F[AuthenticatedCookie[Alg, I]] =
            F.delay(Instant.now()).flatMap { now =>
              val updated = authenticator.copy[Alg, I](lastTouched = Some(now))
              tokenStore.update(updated).map(_ => updated)
            }
        }

      case None =>
        new SignedCookieAuthenticator[F, I, V, Alg](tokenStore, idStore, settings) {
          private[tsec] def validateCookie(
              internal: AuthenticatedCookie[Alg, I],
              raw: SignedCookie[Alg],
              now: Instant
          ): Boolean = raw === internal.content && !internal.isExpired(now)

          private[tsec] def verifyAndRetrieve(signed: SignedCookie[Alg]): F[String] =
            CookieSigner.verifyAndRetrieve[F, Alg](signed, key)

          private[tsec] def sign(message: String, nonce: String): F[SignedCookie[Alg]] =
            CookieSigner.sign[F, Alg](message, nonce, key)

          def refresh(authenticator: AuthenticatedCookie[Alg, I]): F[AuthenticatedCookie[Alg, I]] =
            F.pure(authenticator)
        }
    }

}
