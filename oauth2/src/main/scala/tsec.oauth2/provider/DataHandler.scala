package tsec.oauth2.provider

import java.time.Instant

import cats.implicits._
import cats.effect.Sync

import scala.concurrent.duration._
import scala.concurrent.duration.FiniteDuration

/**
  * Provide accessing to data storage for using OAuth 2.0.
  */
trait DataHandler[F[_], U] extends AuthorizationHandler[F, U] with ProtectedResourceHandler[F, U]

/**
  * Access token
  *
  * @param token Access token is used to authentication.
  * @param refreshToken Refresh token is used to re-issue access token.
  * @param scope Inform the client of the scope of the access token issued.
  * @param lifeTime Life of the access token since its creation.
  * @param createdAt Access token is created date.
  * @param params Additional parameters to add information/restriction on given Access token.
  */
final case class AccessToken(
                              token: String,
                              refreshToken: Option[String],
                              scope: Option[String],
                              lifeTime: Option[FiniteDuration],
                              createdAt: Instant,
                              params: Map[String, String] = Map.empty[String, String]
) {
  def isExpired[F[_]](implicit F: Sync[F]): F[Boolean] = expiresIn.map(_.exists(_.toMillis < 0))

  def expiresIn[F[_]](implicit F: Sync[F]): F[Option[FiniteDuration]] = lifeTime traverse { l =>
    val expTime = createdAt.toEpochMilli + l.toMillis
    for{
      now <- F.delay(System.currentTimeMillis)
      t <- F.pure(((expTime - now) / 1000) milli)
    } yield t
  }
}

/**
  * Authorized information
  *
  * @param user Authorized user which is registered on system.
  * @param clientId Using client id which is registered on system.
  * @param scope Inform the client of the scope of the access token issued.
  * @param redirectUri This value is used by Authorization Code Grant.
  */
final case class AuthInfo[U](user: U, clientId: Option[String], scope: Option[String], redirectUri: Option[String])
