package tsec.oauth2.provider
package grantHandler

import cats.data.EitherT
import cats.effect.Sync
import cats.implicits._
import tsec.oauth2.provider.ValidatedRequest._

class ClientCredentialsGrantHandler[F[_], U](handler: ClientCredentialsHandler[F, U]) extends GrantHandler[F, U] {
  type A = ValidatedClientCredentials
  def handleRequest(
      req: ValidatedClientCredentials
  )(implicit F: Sync[F]): EitherT[F, OAuthError, GrantHandlerResult[U]] =
    for {
      _ <- EitherT[F, OAuthError, Unit](
        handler
          .validateClient(req)
          .map(
            isValid => Either.cond(isValid, (), InvalidClient("Invalid client or client is not authorized"): OAuthError)
          )
      )
      user <- EitherT[F, OAuthError, U](
        handler
          .findUser(req)
          .map(_.toRight(InvalidGrant("client_id or client_secret or scope is incorrect")))
      )
      authInfo = AuthInfo(user, Some(req.clientCredential.clientId), req.scope, None)
      grantResult <- EitherT(
        issueAccessToken(handler, authInfo).attempt
          .map(_.leftMap(t => FailedToIssueAccessToken(t.getMessage): OAuthError))
      )
    } yield grantResult
}

trait ClientCredentialsHandler[F[_], U] extends IssueAccessToken[F, U] {

  /**
    * Verify proper client with parameters for issue an access token.
    * Note that per the OAuth Specification, a Client may be valid if it only contains a client ID but no client
    * secret (common with Public Clients). However, if the registered client has a client secret value the specification
    * requires that a client secret must always be provided and verified for that client ID.
    *
    * @param request Request sent by client.
    * @return true if request is a regular client, false if request is a illegal client.
    */
  def validateClient(request: ValidatedClientCredentials): F[Boolean]

  /**
    * Authenticate the user that issued the authorization request.
    * Client credential, Password and Implicit Grant call this method.
    *
    * @param request Request sent by client.
    */
  def findUser(request: ValidatedClientCredentials): F[Option[U]]

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
