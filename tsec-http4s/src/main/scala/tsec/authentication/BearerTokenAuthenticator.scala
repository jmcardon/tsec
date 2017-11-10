package tsec.authentication

import java.time.Instant

import cats.MonadError
import cats.data.OptionT
import org.http4s.headers.Authorization
import org.http4s.{AuthScheme, Credentials, Request, Response}
import tsec.common._
import cats.syntax.all._

import scala.concurrent.duration._

sealed abstract class BearerTokenAuthenticator[F[_], I, V] private[tsec]  (
    val expiry: FiniteDuration,
    val maxIdle: Option[FiniteDuration]
) extends AuthenticatorService[F, I, V, TSecBearerToken[I]] {

  def withIdentityStore(newStore: BackingStore[F, I, V]): BearerTokenAuthenticator[F, I, V]

  def withTokenStore(
      newStore: BackingStore[F, SecureRandomId, TSecBearerToken[I]]
  ): BearerTokenAuthenticator[F, I, V]
}

final case class TSecBearerToken[I](
    id: SecureRandomId,
    identity: I,
    expiry: Instant,
    lastTouched: Option[Instant]
) extends Authenticator[I]

object BearerTokenAuthenticator {
  def apply[F[_], I, V](
      tokenStore: BackingStore[F, SecureRandomId, TSecBearerToken[I]],
      identityStore: BackingStore[F, I, V],
      settings: TSecTokenSettings,
  )(implicit M: MonadError[F, Throwable]): BearerTokenAuthenticator[F, I, V] =
    new BearerTokenAuthenticator[F, I, V](settings.expiryDuration, settings.maxIdle) {

      def withIdentityStore(newStore: BackingStore[F, I, V]): BearerTokenAuthenticator[F, I, V] =
        apply(tokenStore, newStore, settings)

      def withTokenStore(
          newStore: BackingStore[F, SecureRandomId, TSecBearerToken[I]]
      ): BearerTokenAuthenticator[F, I, V] =
        apply(newStore, identityStore, settings)

      private def validate(token: TSecBearerToken[I]) = {
        val now = Instant.now()
        !token.isExpired(now) && settings.maxIdle.forall(!token.isTimedout(now, _))
      }

      def extractAndValidate(request: Request[F]): OptionT[F, SecuredRequest[F, V, TSecBearerToken[I]]] =
        for {
          rawToken  <- OptionT.fromOption[F](extractBearerToken[F](request))
          token     <- tokenStore.get(SecureRandomId.coerce(rawToken))
          _         <- if (validate(token)) OptionT.pure(()) else OptionT.none
          refreshed <- refresh(token)
          identity  <- identityStore.get(token.identity)
        } yield SecuredRequest(request, identity, refreshed)

      def create(body: I): OptionT[F, TSecBearerToken[I]] = {
        val newID = SecureRandomId.generate
        val now   = Instant.now()
        val newToken: TSecBearerToken[I] = TSecBearerToken(
          newID,
          body,
          now.plusSeconds(settings.expiryDuration.toSeconds),
          settings.maxIdle.map(_ => now)
        )
        OptionT.liftF(tokenStore.put(newToken))
      }

      def update(authenticator: TSecBearerToken[I]): OptionT[F, TSecBearerToken[I]] =
        OptionT.liftF(tokenStore.update(authenticator))

      def discard(authenticator: TSecBearerToken[I]): OptionT[F, TSecBearerToken[I]] =
        OptionT.liftF(tokenStore.delete(authenticator.id)).map(_ => authenticator)

      def renew(authenticator: TSecBearerToken[I]): OptionT[F, TSecBearerToken[I]] = {
        val now = Instant.now()
        val newToken = authenticator.copy(
          expiry = now.plusSeconds(settings.expiryDuration.toSeconds),
          lastTouched = settings.maxIdle.map(_ => now)
        )
        update(newToken)
      }

      def refresh(authenticator: TSecBearerToken[I]): OptionT[F, TSecBearerToken[I]] = settings.maxIdle match {
        case None =>
          OptionT.pure(authenticator)
        case Some(idleTime) =>
          val now = Instant.now()
          update(authenticator.copy(lastTouched = Some(now.plusSeconds(idleTime.toSeconds))))
      }

      def embed(response: Response[F], authenticator: TSecBearerToken[I]): Response[F] =
        response.putHeaders(Authorization(Credentials.Token(AuthScheme.Bearer, authenticator.id)))

      def afterBlock(response: Response[F], authenticator: TSecBearerToken[I]): OptionT[F, Response[F]] =
        settings.maxIdle match {
          case Some(_) =>
            OptionT.pure[F](embed(response, authenticator))
          case None =>
            OptionT.pure[F](response)
        }
    }
}
