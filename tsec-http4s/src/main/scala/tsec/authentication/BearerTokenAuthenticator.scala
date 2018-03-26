package tsec.authentication

import java.time.Instant

import cats.data.OptionT
import cats.effect.Sync
import cats.syntax.all._
import org.http4s.headers.Authorization
import org.http4s.{AuthScheme, Credentials, Request, Response}
import tsec.common._

import scala.concurrent.duration._

sealed abstract class BearerTokenAuthenticator[F[_]: Sync, I, V] private[tsec] (
    val expiry: FiniteDuration,
    val maxIdle: Option[FiniteDuration]
) extends Authenticator[F, I, V, TSecBearerToken[I]] {

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
)

object TSecBearerToken {
  implicit def auth[I]: AuthToken[TSecBearerToken[I]] = new AuthToken[TSecBearerToken[I]] {
    def expiry(a: TSecBearerToken[I]): Instant = a.expiry

    def lastTouched(a: TSecBearerToken[I]): Option[Instant] =
      a.lastTouched
  }
}

object BearerTokenAuthenticator {
  def apply[F[_], I, V](
      tokenStore: BackingStore[F, SecureRandomId, TSecBearerToken[I]],
      identityStore: BackingStore[F, I, V],
      settings: TSecTokenSettings
  )(implicit F: Sync[F]): BearerTokenAuthenticator[F, I, V] =
    new BearerTokenAuthenticator[F, I, V](settings.expiryDuration, settings.maxIdle) {

      def withIdentityStore(newStore: BackingStore[F, I, V]): BearerTokenAuthenticator[F, I, V] =
        apply(tokenStore, newStore, settings)

      def withTokenStore(
          newStore: BackingStore[F, SecureRandomId, TSecBearerToken[I]]
      ): BearerTokenAuthenticator[F, I, V] =
        apply(newStore, identityStore, settings)

      private def validateAndRefresh(token: TSecBearerToken[I]): OptionT[F, TSecBearerToken[I]] =
        OptionT.liftF(F.delay(Instant.now())).flatMap { now =>
          if (!token.isExpired(now) && settings.maxIdle.forall(!token.isTimedOut(now, _)))
            OptionT.liftF(refresh(token))
          else
            OptionT.none
        }

      def extractRawOption(request: Request[F]): Option[String] = extractBearerToken[F](request)

      def parseRaw(raw: String, request: Request[F]): OptionT[F, SecuredRequest[F, V, TSecBearerToken[I]]] =
        (for {
          token     <- tokenStore.get(SecureRandomId.coerce(raw))
          refreshed <- validateAndRefresh(token)
          identity  <- identityStore.get(token.identity)
        } yield SecuredRequest(request, identity, refreshed))
          .handleErrorWith(_ => OptionT.none)

      def create(body: I): F[TSecBearerToken[I]] =
        for {
          now <- F.delay(Instant.now())
          newToken = TSecBearerToken(
            SecureRandomId.Strong.generate,
            body,
            now.plusSeconds(settings.expiryDuration.toSeconds),
            settings.maxIdle.map(_ => now)
          )
          out <- tokenStore.put(newToken)
        } yield out

      def update(authenticator: TSecBearerToken[I]): F[TSecBearerToken[I]] =
        tokenStore.update(authenticator)

      def discard(authenticator: TSecBearerToken[I]): F[TSecBearerToken[I]] =
        tokenStore.delete(authenticator.id).map(_ => authenticator)

      def renew(authenticator: TSecBearerToken[I]): F[TSecBearerToken[I]] =
        for {
          now <- F.delay(Instant.now())
          updated <- tokenStore.update(
            authenticator.copy(
              expiry = now.plusSeconds(settings.expiryDuration.toSeconds),
              lastTouched = settings.maxIdle.map(_ => now)
            )
          )
        } yield updated

      def refresh(authenticator: TSecBearerToken[I]): F[TSecBearerToken[I]] = settings.maxIdle match {
        case None =>
          F.pure(authenticator)
        case Some(idleTime) =>
          for {
            now     <- F.delay(Instant.now())
            updated <- tokenStore.update(authenticator.copy(lastTouched = Some(now.plusSeconds(idleTime.toSeconds))))
          } yield updated
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
