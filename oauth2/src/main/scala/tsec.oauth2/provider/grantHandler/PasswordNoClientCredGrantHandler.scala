package tsec.oauth2.provider
package grantHandler

import cats.data.EitherT
import cats.effect.Sync
import cats.implicits._
import tsec.oauth2.provider.ValidatedRequest._

class PasswordNoClientCredGrantHandler[F[_], U](handler: PasswordNoClientCredHandler[F, U]) extends GrantHandler[F, U] {
  type A = ValidatedPasswordNoClientCred
  def handleRequest(
      req: ValidatedPasswordNoClientCred
  )(implicit F: Sync[F]): EitherT[F, OAuthError, GrantHandlerResult[U]] =
    for {
      user <- EitherT(
        handler.findUser(None, req).map(_.toRight(InvalidGrant("username or password is incorrect")))
      )
      authInfo = AuthInfo(user, None, req.scope, None)
      grantResult <- EitherT(
        issueAccessToken(handler, authInfo).attempt
          .map(_.leftMap(t => FailedToIssueAccessToken(t.getMessage): OAuthError))
      )
    } yield grantResult
}

trait PasswordNoClientCredHandler[F[_], U] extends IssueAccessToken[F, U] {

  /**
    * Authenticate the user that issued the authorization request.
    * Client credential, Password and Implicit Grant call this method.
    *
    * @param maybeCredential client credential parsed from request
    * @param request Request sent by client.
    */
  def findUser(maybeCredential: Option[ClientCredential], request: ValidatedPasswordNoClientCred): F[Option[U]]

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
