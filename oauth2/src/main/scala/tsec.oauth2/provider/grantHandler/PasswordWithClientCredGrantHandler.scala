package tsec.oauth2.provider
package grantHandler

import cats.data.EitherT
import cats.effect.Sync
import cats.implicits._
import tsec.oauth2.provider.ValidatedRequest.ValidatedPasswordWithClientCred

/**
  * Per the OAuth2 specification, client credentials are required for all grant types except password, where it is up
  * to the authorization provider whether to make them required or not.
  */
class PasswordWithClientCredGrantHandler[F[_], U](handler: PasswordWithClientCredHandler[F, U])
    extends GrantHandler[F, U] {
  type A = ValidatedPasswordWithClientCred
  def handleRequest(
      req: ValidatedPasswordWithClientCred
  )(implicit F: Sync[F]): EitherT[F, OAuthError, GrantHandlerResult[U]] =
    for {
      _ <- EitherT(
        handler
          .validateClient(req)
          .map(
            isValid => Either.cond(isValid, (), InvalidClient("Invalid client or client is not authorized"): OAuthError)
          )
      )
      user <- EitherT(
        handler
          .findUser(req)
          .map(_.toRight(InvalidGrant("username or password is incorrect")))
      )
      authInfo = AuthInfo(user, Some(req.clientCredential.clientId), req.scope, None)
      grantResult <- EitherT(
        issueAccessToken(handler, authInfo).attempt
          .map(_.leftMap(t => FailedToIssueAccessToken(t.getMessage): OAuthError))
      )
    } yield grantResult
}

trait PasswordWithClientCredHandler[F[_], U] extends IssueAccessToken[F, U] {

  /**
    * Authenticate the user that issued the authorization request.
    * Client credential, Password and Implicit Grant call this method.
    *
    * @param request Request sent by client.
    */
  def findUser(request: ValidatedPasswordWithClientCred): F[Option[U]]

  /**
    * Verify proper client with parameters for issue an access token.
    * Note that per the OAuth Specification, a Client may be valid if it only contains a client ID but no client
    * secret (common with Public Clients). However, if the registered client has a client secret value the specification
    * requires that a client secret must always be provided and verified for that client ID.
    *
    * @param request Request sent by client.
    * @return true if request is a regular client, false if request is a illegal client.
    */
  def validateClient(request: ValidatedPasswordWithClientCred): F[Boolean]
}
