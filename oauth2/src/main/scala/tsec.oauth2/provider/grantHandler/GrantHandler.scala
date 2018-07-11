package tsec.oauth2.provider
package grantHandler

import cats.data.EitherT
import cats.effect.Sync
import cats.implicits._

import scala.concurrent.duration.FiniteDuration

sealed abstract class GrantType extends Product with Serializable {
  def name: String
}

object GrantType {
  val header = "grant_type"

  case object AuthorizationCode extends GrantType {
    def name: String = "authorization_code"
  }

  case object RefreshToken extends GrantType {
    def name: String = "refresh_token"
  }

  case object ClientCrendentials extends GrantType {
    def name: String = "client_credentials"
  }

  case object Password extends GrantType {
    def name: String = "password"
  }

  case object Implicit extends GrantType {
    def name: String = "implicit"
  }

  val strToGrantType = Map(
    AuthorizationCode.name  -> AuthorizationCode,
    RefreshToken.name       -> RefreshToken,
    ClientCrendentials.name -> ClientCrendentials,
    Password.name           -> Password,
    Implicit.name           -> Implicit
  )
}

final case class GrantHandlerResult[U](
    authInfo: AuthInfo[U],
    tokenType: String,
    accessToken: String,
    expiresIn: Option[FiniteDuration],
    refreshToken: Option[String],
    scope: Option[String],
    params: Map[String, String]
)

trait GrantHandler[F[_], U] {
  type A
  def handleRequest(req: A)(implicit F: Sync[F]): EitherT[F, OAuthError, GrantHandlerResult[U]]

  /**
    * Returns valid access token.
    */
  private[oauth2] def issueAccessToken[U](
      handler: IssueAccessToken[F, U],
      authInfo: AuthInfo[U]
  )(implicit F: Sync[F]): F[GrantHandlerResult[U]] =
    for {
      token <- handler.getStoredAccessToken(authInfo)
      t <- token match {
        case Some(token) =>
          token.isExpired.flatMap { shouldRefresh =>
            if (shouldRefresh)
              token.refreshToken
                .map {
                  handler.refreshAccessToken(authInfo, _)
                }
                .getOrElse {
                  handler.createAccessToken(authInfo)
                } else
              F.pure(token)
          }
        case None => handler.createAccessToken(authInfo)
      }
      expiresIn <- t.expiresIn
    } yield GrantHandler.createGrantHandlerResult(authInfo, t, expiresIn)
}

object GrantHandler {
  type Aux[F[_], U, A0] = GrantHandler[F, U] {
    type A = A0
  }

  private[grantHandler] def createGrantHandlerResult[U](
      authInfo: AuthInfo[U],
      accessToken: AccessToken,
      expiresIn: Option[FiniteDuration]
  ) =
    GrantHandlerResult(
      authInfo,
      "Bearer",
      accessToken.token,
      expiresIn,
      accessToken.refreshToken,
      accessToken.scope,
      accessToken.params
    )
}

trait IssueAccessToken[F[_], U] {

  /**
    * Creates a new access token by authorized information.
    *
    * @param authInfo This value is already authorized by system.
    * @return Access token returns to client.
    */
  def createAccessToken(authInfo: AuthInfo[U]): F[AccessToken]

  /**
    * Returns stored access token by authorized information.
    *
    * If want to create new access token then have to return None
    *
    * @param authInfo This value is already authorized by system.
    * @return Access token returns to client.
    */
  def getStoredAccessToken(authInfo: AuthInfo[U]): F[Option[AccessToken]]

  /**
    * Creates a new access token by refreshToken.
    *
    * @param authInfo This value is already authorized by system.
    * @return Access token returns to client.
    */
  def refreshAccessToken(authInfo: AuthInfo[U], refreshToken: String): F[AccessToken]
}
