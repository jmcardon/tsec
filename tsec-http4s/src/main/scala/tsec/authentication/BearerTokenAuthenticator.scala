package tsec.authentication

import java.time.Instant

import cats.MonadError
import cats.data.OptionT
import cats.effect.Sync
import org.http4s.headers.Authorization
import org.http4s.{AuthScheme, Credentials, Request, Response}
import tsec.common._
import cats.syntax.all._

import scala.concurrent.duration._

sealed abstract class BearerTokenAuthenticator[F[_], I, V] private[tsec] (
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
          if (!token.isExpired(now) && settings.maxIdle.forall(!token.isTimedout(now, _)))
            refresh(token)
          else
            OptionT.none
        }

      def extractRawOption(request: Request[F]): Option[String] = extractBearerToken[F](request)

      def parseRaw(raw: String, request: Request[F]): OptionT[F, SecuredRequest[F, V, TSecBearerToken[I]]] =
        for {
          token     <- tokenStore.get(SecureRandomId.coerce(raw))
          refreshed <- validateAndRefresh(token)
          identity  <- identityStore.get(token.identity)
        } yield SecuredRequest(request, identity, refreshed)

      def extractAndValidate(request: Request[F]): OptionT[F, SecuredRequest[F, V, TSecBearerToken[I]]] =
        extractRawOption(request) match {
          case Some(raw) => parseRaw(raw, request)
          case None      => OptionT.none
        }

      def create(body: I): OptionT[F, TSecBearerToken[I]] =
        OptionT.liftF(for {
          now <- F.delay(Instant.now())
          newToken = TSecBearerToken(
            SecureRandomId.generate,
            body,
            now.plusSeconds(settings.expiryDuration.toSeconds),
            settings.maxIdle.map(_ => now)
          )
          out <- tokenStore.put(newToken)
        } yield out)

      def update(authenticator: TSecBearerToken[I]): OptionT[F, TSecBearerToken[I]] =
        OptionT.liftF(tokenStore.update(authenticator))

      def discard(authenticator: TSecBearerToken[I]): OptionT[F, TSecBearerToken[I]] =
        OptionT.liftF(tokenStore.delete(authenticator.id)).map(_ => authenticator)

      def renew(authenticator: TSecBearerToken[I]): OptionT[F, TSecBearerToken[I]] =
        OptionT.liftF(for {
          now <- F.delay(Instant.now())
          updated <- tokenStore.update(
            authenticator.copy(
              expiry = now.plusSeconds(settings.expiryDuration.toSeconds),
              lastTouched = settings.maxIdle.map(_ => now)
            )
          )
        } yield updated)

      def refresh(authenticator: TSecBearerToken[I]): OptionT[F, TSecBearerToken[I]] = settings.maxIdle match {
        case None =>
          OptionT.pure(authenticator)
        case Some(idleTime) =>
          OptionT.liftF(for {
            now     <- F.delay(Instant.now())
            updated <- tokenStore.update(authenticator.copy(lastTouched = Some(now.plusSeconds(idleTime.toSeconds))))
          } yield updated)
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
