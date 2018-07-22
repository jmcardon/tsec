package tsec.oauth2.provider
package grantHandler

import cats.data.EitherT
import cats.effect.Sync
import cats.implicits._
import tsec.oauth2.provider.ValidatedRequest._

class AuthorizationCodeGrantHandler[F[_], U](handler: AuthorizationCodeHandler[F, U]) extends GrantHandler[F, U] {
  type A = ValidatedAuthorizationCode
  def handleRequest(
      req: ValidatedAuthorizationCode
  )(implicit F: Sync[F]): EitherT[F, OAuthError, GrantHandlerResult[U]] =
    for {
      _ <- EitherT(
        handler
          .validateClient(req)
          .map(
            isValid => Either.cond(isValid, (), InvalidClient("Invalid client or client is not authorized"): OAuthError)
          )
      )
      auth <- EitherT[F, OAuthError, AuthInfo[U]](
        handler
          .findAuthInfoByCode(req.code)
          .map(_.toRight(InvalidGrant("Authorized information is not found by the code")))
      )
      _ <- EitherT
        .cond[F](auth.clientId.contains(req.clientCredential.clientId), (), InvalidClient("invalid clientId"))
      _ <- EitherT.cond[F](
        auth.redirectUri.isEmpty || (auth.redirectUri.isDefined && auth.redirectUri == req.redirectUri),
        (),
        RedirectUriMismatch
      )
      grantResult <- EitherT(
        issueAccessToken(handler, auth).attempt
          .map(_.leftMap(t => FailedToIssueAccessToken(t.getMessage): OAuthError))
      )
      _ <- EitherT(
        handler.deleteAuthCode(req.code).attempt.map(_.leftMap(t => FailedToDeleteAuthCode(t.getMessage): OAuthError))
      )
    } yield grantResult
}

trait AuthorizationCodeHandler[F[_], U] extends IssueAccessToken[F, U] {

  /**
    * Verify proper client with parameters for issue an access token.
    * Note that per the OAuth Specification, a Client may be valid if it only contains a client ID but no client
    * secret (common with Public Clients). However, if the registered client has a client secret value the specification
    * requires that a client secret must always be provided and verified for that client ID.
    *
    * @param request Request sent by client.
    * @return true if request is a regular client, false if request is a illegal client.
    */
  def validateClient(request: ValidatedAuthorizationCode): F[Boolean]

  /**
    * Find authorized information by authorization code.
    *
    * If you don't support Authorization Code Grant then doesn't need implementing.
    *
    * @param code Client sends authorization code which is registered by system.
    * @return Return authorized information that matched the code.
    */
  def findAuthInfoByCode(code: String): F[Option[AuthInfo[U]]]

  /**
    * Deletes an authorization code.
    *
    * Called when an AccessToken has been successfully issued via an authorization code.
    *
    * If you don't support Authorization Code Grant, then you don't need to implement this
    * method.
    *
    * @param code Client-sent authorization code
    */
  def deleteAuthCode(code: String): F[Unit]
}
