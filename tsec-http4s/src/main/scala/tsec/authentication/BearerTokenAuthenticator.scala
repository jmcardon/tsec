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
) extends Authenticator[F, I, V, TSecBearerToken[I]]

private[tsec] abstract class BTAuthImpl[F[_], I, V](
    expiry: FiniteDuration,
    maxIdle: Option[FiniteDuration],
    tokenStore: BackingStore[F, SecureRandomId, TSecBearerToken[I]],
    identityStore: IdentityStore[F, I, V]
)(implicit F: Sync[F])
    extends BearerTokenAuthenticator[F, I, V](expiry, maxIdle) {
  private[tsec] def validateAndRefresh(token: TSecBearerToken[I]): OptionT[F, TSecBearerToken[I]]

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
        now.plusSeconds(expiry.toSeconds),
        touch(now)
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
          expiry = now.plusSeconds(expiry.toSeconds),
          lastTouched = touch(now)
        )
      )
    } yield updated

  def embed(response: Response[F], authenticator: TSecBearerToken[I]): Response[F] =
    response.putHeaders(Authorization(Credentials.Token(AuthScheme.Bearer, authenticator.id)))

  def afterBlock(response: Response[F], authenticator: TSecBearerToken[I]): OptionT[F, Response[F]] =
    OptionT.pure[F](response)
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
      identityStore: IdentityStore[F, I, V],
      settings: TSecTokenSettings
  )(implicit F: Sync[F]): BearerTokenAuthenticator[F, I, V] =
    settings.maxIdle match {
      case Some(mIdle) =>
        new BTAuthImpl[F, I, V](settings.expiryDuration, settings.maxIdle, tokenStore, identityStore) {
          private[tsec] def validateAndRefresh(token: TSecBearerToken[I]) =
            OptionT.liftF(F.delay(Instant.now())).flatMap { now =>
              if (!token.isExpired(now) && !token.isTimedOut(now, mIdle))
                OptionT.liftF(refresh(token))
              else
                OptionT.none
            }

          def refresh(authenticator: TSecBearerToken[I]): F[TSecBearerToken[I]] =
            for {
              now <- F.delay(Instant.now())
              updated <- tokenStore.update(
                authenticator.copy(lastTouched = Some(now.plusSeconds(mIdle.toSeconds)))
              )
            } yield updated
        }

      case None =>
        new BTAuthImpl[F, I, V](settings.expiryDuration, settings.maxIdle, tokenStore, identityStore) {
          private[tsec] def validateAndRefresh(token: TSecBearerToken[I]) =
            OptionT.liftF(F.delay(Instant.now())).flatMap { now =>
              if (!token.isExpired(now))
                OptionT.pure[F](token)
              else
                OptionT.none
            }

          def refresh(authenticator: TSecBearerToken[I]): F[TSecBearerToken[I]] =
            F.pure(authenticator)
        }
    }
}
