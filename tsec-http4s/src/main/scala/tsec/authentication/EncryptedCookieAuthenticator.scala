package tsec.authentication

import java.time.Instant
import java.util.UUID

import cats.{Monad, MonadError}
import cats.data.OptionT
import io.circe.{Decoder, Encoder}
import io.circe.parser.decode
import org.http4s._
import tsec.cipher.symmetric._
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

sealed abstract class EncryptedCookieAuthenticator[F[_], A, I, V](implicit auth: AuthEncryptor[A])
    extends AuthenticatorEV[F, A, I, V, AuthEncryptedCookie[?, I]]

sealed abstract class StatefulECAuthenticator[F[_], A, I, V](implicit auth: AuthEncryptor[A])
    extends EncryptedCookieAuthenticator[F, A, I, V] {
  def withKey(newKey: SecretKey[A]): StatefulECAuthenticator[F, A, I, V]

  def withSettings(settings: TSecCookieSettings): StatefulECAuthenticator[F, A, I, V]

  def withIdentityStore(newStore: BackingStore[F, I, V]): StatefulECAuthenticator[F, A, I, V]

  def withTokenStore(
      newStore: BackingStore[F, UUID, AuthEncryptedCookie[A, I]]
  ): StatefulECAuthenticator[F, A, I, V]
}

sealed abstract class StatelessECAuthenticator[F[_], A, I, V](implicit auth: AuthEncryptor[A])
    extends EncryptedCookieAuthenticator[F, A, I, V] {
  def withKey(newKey: SecretKey[A]): StatelessECAuthenticator[F, A, I, V]

  def withSettings(settings: TSecCookieSettings): StatelessECAuthenticator[F, A, I, V]

  def withIdentityStore(newStore: BackingStore[F, I, V]): StatelessECAuthenticator[F, A, I, V]
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
    lastTouched.exists(
      _.toInstant
        .plusSeconds(timeOut.toSeconds)
        .isBefore(now)
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
      c: Cookie
  ): AuthEncryptedCookie[A, Id] =
    AuthEncryptedCookie[A, Id](
      internal.id,
      c.name,
      content,
      internal.messageId,
      internal.expiry,
      internal.lastTouched,
      c.secure,
      c.httpOnly,
      c.domain,
      c.path,
      c.extension
    )

}

object EncryptedCookieAuthenticator {

  /***
    * The default Encrypted cookie Authenticator, with a backing store.
    *
    * @param settings the cookie settings
    * @param tokenStore the token backing store
    * @param identityStore the backing store of the identity
    * @param key the symmetric signing key
    * @tparam F the effect type
    * @tparam Alg the symmetric key algorithm to use authenticated encryption
    * @tparam I the id type for a user
    * @tparam V the expected user type, V aka value
    * @return An encrypted cookie authenticator
    */
  def withBackingStore[F[_], Alg: AuthEncryptor, I: Decoder: Encoder, V](
      settings: TSecCookieSettings,
      tokenStore: BackingStore[F, UUID, AuthEncryptedCookie[Alg, I]],
      identityStore: BackingStore[F, I, V],
      key: SecretKey[Alg]
  )(implicit M: MonadError[F, Throwable]): StatefulECAuthenticator[F, Alg, I, V] =
    new StatefulECAuthenticator[F, Alg, I, V] {

      /**
        * Return a new instance with a modified key
        */
      def withKey(newKey: SecretKey[Alg]): StatefulECAuthenticator[F, Alg, I, V] =
        withBackingStore[F, Alg, I, V](
          settings,
          tokenStore,
          identityStore,
          newKey
        )

      /** Return a new instance with modified settings
        *
        */
      def withSettings(settings: TSecCookieSettings): StatefulECAuthenticator[F, Alg, I, V] =
        withBackingStore[F, Alg, I, V](
          settings,
          tokenStore,
          identityStore,
          key
        )

      /** Return a new instance with a different identity store
        *
        */
      def withIdentityStore(newStore: BackingStore[F, I, V]): StatefulECAuthenticator[F, Alg, I, V] =
        withBackingStore[F, Alg, I, V](
          settings,
          tokenStore,
          newStore,
          key
        )

      /** Return a new instance with a different token store
        *
        */
      def withTokenStore(
          newStore: BackingStore[F, UUID, AuthEncryptedCookie[Alg, I]]
      ): StatefulECAuthenticator[F, Alg, I, V] =
        withBackingStore[F, Alg, I, V](
          settings,
          newStore,
          identityStore,
          key
        )

      /** Generate our AAD: A sort of nonce to use for authentication withour encryption
        *
        */
      private def generateAAD(message: String) =
        AAD((message + Instant.now.toEpochMilli).utf8Bytes.hash[SHA1])

      /** Validate the cookie against the raw representation, and
        * validate against possibly expiration or timeout
        *
        */
      private def validateCookie(
          internal: AuthEncryptedCookie[Alg, I],
          raw: AEADCookie[Alg],
          now: Instant
      ): Boolean =
        internal.content === raw && !internal.isExpired(now) && !settings.maxIdle.exists(internal.isTimedout(now, _))

      /** lift the validation onto an optionT
        *
        */
      private def validateCookieT(
          internal: AuthEncryptedCookie[Alg, I],
          raw: AEADCookie[Alg],
          now: Instant
      ): OptionT[F, Unit] =
        if (validateCookie(internal, raw, now)) OptionT.pure[F](()) else OptionT.none

      /** Extract our encrypted cookie frmo a request.
        * We validate using our symmetric key, extracting the tokenId from the encrypted value, and then retrieving
        * the identity from the retrieved object.
        *
        * @return
        */
      def extractAndValidate(request: Request[F]): OptionT[F, SecuredRequest[F, AuthEncryptedCookie[Alg, I], V]] = {
        val now = Instant.now()
        for {
          rawCookie <- cookieFromRequest[F](settings.cookieName, request)
          coerced = AEADCookie.fromRaw[Alg](rawCookie.content)
          contentRaw <- OptionT.liftF(M.fromEither(AEADCookieEncryptor.retrieveFromSigned[Alg](coerced, key)))
          tokenId    <- uuidFromRaw[F](contentRaw)
          authed     <- tokenStore.get(tokenId)
          _          <- validateCookieT(authed, coerced, now)
          refreshed  <- refresh(authed)
          identity   <- identityStore.get(authed.messageId)
        } yield SecuredRequest(request, refreshed, identity)
      }

      /** Create a new cookie from the id field of a particular user.
        *
        */
      def create(body: I): OptionT[F, AuthEncryptedCookie[Alg, I]] = {
        val cookieId    = UUID.randomUUID()
        val now         = Instant.now()
        val expiry      = HttpDate.unsafeFromInstant(now.plusSeconds(settings.expiryDuration.toSeconds))
        val lastTouched = settings.maxIdle.map(_ => HttpDate.unsafeFromInstant(now))
        val messageBody = cookieId.toString
        for {
          encrypted <- OptionT.liftF(
            M.fromEither(AEADCookieEncryptor.signAndEncrypt[Alg](messageBody, generateAAD(messageBody), key))
          )
          cookie <- OptionT.pure[F](
            AuthEncryptedCookie.build[Alg, I](cookieId, encrypted, body, expiry, lastTouched, settings)
          )
          _ <- OptionT.liftF(tokenStore.put(cookie))
        } yield cookie
      }

      /** Update our authenticator in the backing store.
        *
        */
      def update(authenticator: AuthEncryptedCookie[Alg, I]): OptionT[F, AuthEncryptedCookie[Alg, I]] =
        OptionT.liftF(tokenStore.update(authenticator)).mapFilter {
          case 1 => Some(authenticator)
          case _ => None
        }

      /** Discard our authenticator from the backing store
        *
        */
      def discard(authenticator: AuthEncryptedCookie[Alg, I]): OptionT[F, AuthEncryptedCookie[Alg, I]] =
        OptionT.liftF(tokenStore.delete(authenticator.id)).mapFilter {
          case 1 => Some(authenticator)
          case _ => None
        }

      /** Renew, aka reset both the expiry as well as the last touched (if present) value
        *
        */
      def renew(authenticator: AuthEncryptedCookie[Alg, I]): OptionT[F, AuthEncryptedCookie[Alg, I]] = {
        val now = Instant.now()
        settings.maxIdle match {
          case Some(_) =>
            val updated = authenticator.copy[Alg, I](
              lastTouched = Some(HttpDate.unsafeFromInstant(now)),
              expiry = HttpDate.unsafeFromInstant(now.plusSeconds(settings.expiryDuration.toSeconds))
            )
            OptionT.liftF(tokenStore.update(updated)).map(_ => updated)
          case None =>
            val updated = authenticator.copy[Alg, I](
              expiry = HttpDate.unsafeFromInstant(now.plusSeconds(settings.expiryDuration.toSeconds))
            )
            OptionT.liftF(tokenStore.update(updated)).map(_ => updated)
        }
      }

      /** Touch our authenticator. Only used for sliding window expiration. Otherwise, it will be a no-op.
        *
        */
      def refresh(authenticator: AuthEncryptedCookie[Alg, I]): OptionT[F, AuthEncryptedCookie[Alg, I]] =
        settings.maxIdle match {
          case Some(idleTime) =>
            val now = Instant.now()
            val updated = authenticator.copy[Alg, I](
              lastTouched = Some(HttpDate.unsafeFromInstant(now))
            )
            OptionT.liftF(tokenStore.update(updated)).map(_ => updated)
          case None =>
            OptionT.pure[F](authenticator)
        }

      def embed(response: Response[F], authenticator: AuthEncryptedCookie[Alg, I]): Response[F] =
        response.addCookie(authenticator.toCookie)

      def afterBlock(response: Response[F], authenticator: AuthEncryptedCookie[Alg, I]): OptionT[F, Response[F]] =
        settings.maxIdle match {
          case Some(_) =>
            OptionT.pure[F](response.addCookie(authenticator.toCookie))
          case None =>
            OptionT.pure[F](response)
        }
    }

  /**
    * Generate a stateless cookie authenticator that stores the authentication data, but not a token, in a backing store.
    * Since we have no way to verify that the cookie's expiration and sliding window haven't been modified,
    * we encrypt it as part of the contents
    *
    */
  def stateless[F[_], Alg: AuthEncryptor, I: Decoder: Encoder, V](
      settings: TSecCookieSettings,
      identityStore: BackingStore[F, I, V],
      key: SecretKey[Alg]
  )(implicit M: MonadError[F, Throwable]): StatelessECAuthenticator[F, Alg, I, V] =
    new StatelessECAuthenticator[F, Alg, I, V] {

      def withKey(newKey: SecretKey[Alg]): StatelessECAuthenticator[F, Alg, I, V] =
        stateless[F, Alg, I, V](
          settings,
          identityStore,
          newKey
        )

      def withSettings(settings: TSecCookieSettings): StatelessECAuthenticator[F, Alg, I, V] =
        stateless[F, Alg, I, V](
          settings,
          identityStore,
          key
        )

      def withIdentityStore(newStore: BackingStore[F, I, V]): StatelessECAuthenticator[F, Alg, I, V] =
        stateless[F, Alg, I, V](
          settings,
          newStore,
          key
        )

      private def generateAAD(message: String) =
        AAD((message + Instant.now.toEpochMilli).utf8Bytes.hash[SHA1])

      /** Inside a stateless cookie, we do not have a backing store, thus checking with the AuthEncryptedCookie is
        * useless
        *
        */
      private def validateCookie(
          internal: AuthEncryptedCookie[Alg, I],
          now: Instant
      ): Boolean =
        !internal.isExpired(now) && !settings.maxIdle.exists(internal.isTimedout(now, _))

      private def validateCookieT(
          internal: AuthEncryptedCookie[Alg, I],
          now: Instant
      ): OptionT[F, Unit] =
        if (validateCookie(internal, now)) OptionT.pure[F](()) else OptionT.none

      /** Extract and validate our cookie from a request
        *
        */
      def extractAndValidate(request: Request[F]): OptionT[F, SecuredRequest[F, AuthEncryptedCookie[Alg, I], V]] = {
        val now = Instant.now()
        for {
          rawCookie <- cookieFromRequest[F](settings.cookieName, request)
          coerced = AEADCookie.fromRaw[Alg](rawCookie.content)
          contentRaw <- OptionT.liftF(M.fromEither(AEADCookieEncryptor.retrieveFromSigned[Alg](coerced, key)))
          internal   <- OptionT.liftF(M.fromEither(decode[AuthEncryptedCookie.Internal[I]](contentRaw)))
          authed = AuthEncryptedCookie.build[Alg, I](internal, coerced, rawCookie)
          _         <- validateCookieT(authed, now)
          refreshed <- refresh(authed)
          identity  <- identityStore.get(authed.messageId)
        } yield SecuredRequest(request, refreshed, identity)
      }

      /** Create our cookie
        * In the case of encrypted cookies, we cannot trust the client to avoid tampering.
        * Thus, we unfortunately have to encrypt the expiry data as well
        *
        */
      def create(body: I): OptionT[F, AuthEncryptedCookie[Alg, I]] = {
        val cookieId    = UUID.randomUUID()
        val now         = Instant.now()
        val expiry      = HttpDate.unsafeFromInstant(now.plusSeconds(settings.expiryDuration.toSeconds))
        val lastTouched = settings.maxIdle.map(_ => HttpDate.unsafeFromInstant(now))
        val messageBody = AuthEncryptedCookie.Internal(cookieId, body, expiry, lastTouched).asJson.pretty(JWTPrinter)
        for {
          encrypted <- OptionT.liftF(
            M.fromEither(AEADCookieEncryptor.signAndEncrypt[Alg](messageBody, generateAAD(messageBody), key))
          )
          cookie <- OptionT.pure[F](
            AuthEncryptedCookie.build[Alg, I](cookieId, encrypted, body, expiry, lastTouched, settings)
          )
        } yield cookie
      }

      /*
      Reader's note:
      Since this is a stateless authenticator, update must carry information about expiry and sliding window info
      since this is something that could be manipulated by an attacker.

      We sincerely don't want this, thus renew and refresh also rely on update.
       */
      def update(authenticator: AuthEncryptedCookie[Alg, I]): OptionT[F, AuthEncryptedCookie[Alg, I]] = {
        val serialized = AuthEncryptedCookie
          .Internal(authenticator.id, authenticator.messageId, authenticator.expiry, authenticator.lastTouched)
          .asJson
          .pretty(JWTPrinter)
        for {
          encrypted <- OptionT.liftF(
            M.fromEither(AEADCookieEncryptor.signAndEncrypt[Alg](serialized, generateAAD(serialized), key))
          )
        } yield authenticator.copy[Alg, I](content = encrypted)
      }

      //In this case, since we have no backing store, we can invalidate the token
      //This doesn't work entirely if the person _doesn't_ set the token afterwards.
      def discard(authenticator: AuthEncryptedCookie[Alg, I]): OptionT[F, AuthEncryptedCookie[Alg, I]] =
        OptionT.pure(authenticator.copy[Alg, I](content = AEADCookie.fromRaw[Alg]("invalid"), expiry = HttpDate.now))

      /** Renew all of our cookie's possible expirations.
        * If there is a timeout, refresh that as well. otherwise, simply update the expiry.
        *
        */
      def renew(authenticator: AuthEncryptedCookie[Alg, I]): OptionT[F, AuthEncryptedCookie[Alg, I]] = {
        val now = Instant.now()
        settings.maxIdle match {
          case Some(idleTime) =>
            update(
              authenticator.copy[Alg, I](
                lastTouched = Some(HttpDate.unsafeFromInstant(now)),
                expiry = HttpDate.unsafeFromInstant(now.plusSeconds(settings.expiryDuration.toSeconds))
              )
            )
          case None =>
            update(
              authenticator.copy[Alg, I](
                expiry = HttpDate.unsafeFromInstant(now.plusSeconds(settings.expiryDuration.toSeconds))
              )
            )
        }
      }

      def refresh(authenticator: AuthEncryptedCookie[Alg, I]): OptionT[F, AuthEncryptedCookie[Alg, I]] =
        settings.maxIdle match {
          case Some(_) =>
            update(
              authenticator.copy[Alg, I](
                lastTouched = Some(HttpDate.unsafeFromInstant(Instant.now()))
              )
            )
          case None =>
            OptionT.pure[F](authenticator)
        }

      def embed(response: Response[F], authenticator: AuthEncryptedCookie[Alg, I]): Response[F] =
        response.addCookie(authenticator.toCookie)

      def afterBlock(response: Response[F], authenticator: AuthEncryptedCookie[Alg, I]): OptionT[F, Response[F]] =
        settings.maxIdle match {
          case Some(_) =>
            OptionT.pure[F](response.addCookie(authenticator.toCookie))
          case None =>
            OptionT.pure[F](response)
        }
    }
}
