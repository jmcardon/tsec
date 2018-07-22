package tsec.oauth2.provider
package grantHandler

import cats.implicits._
import cats.data.EitherT
import cats.effect.Sync
import tsec.oauth2.provider.ValidatedRequest._

class ImplicitGrantHandler[F[_], U](handler: ImplicitHandler[F, U]) extends GrantHandler[F, U] {
  type A = ValidatedImplicit
  def handleRequest(
      req: ValidatedImplicit
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
        handler.findUser(req).map(_.toRight(InvalidGrant("user cannot be authenticated")))
      )

      authInfo = AuthInfo(user, Some(req.clientCredential.clientId), req.scope, None)
      token = handler.getStoredAccessToken(authInfo).flatMap { token =>
        val res = token match {
          case Some(token) => F.pure(token)
          case None        => handler.createAccessToken(authInfo)
        }
        for {
          t         <- res
          expiresIn <- t.expiresIn
        } yield
          GrantHandlerResult(
            authInfo,
            "Bearer",
            t.token,
            expiresIn,
            None,
            t.scope,
            t.params
          )
      }
      grantResult <- EitherT(
        token.attempt
          .map(_.leftMap(t => FailedToIssueAccessToken(t.getMessage): OAuthError))
      )
    } yield grantResult
}

trait ImplicitHandler[F[_], U] {

  /**
    * Authenticate the user that issued the authorization request.
    * Client credential, Password and Implicit Grant call this method.
    *
    * @param request Request sent by client.
    */
  def findUser(request: ValidatedImplicit): F[Option[U]]

  /**
    * Verify proper client with parameters for issue an access token.
    * Note that per the OAuth Specification, a Client may be valid if it only contains a client ID but no client
    * secret (common with Public Clients). However, if the registered client has a client secret value the specification
    * requires that a client secret must always be provided and verified for that client ID.
    *
    * @param request Request sent by client.
    * @return true if request is a regular client, false if request is a illegal client.
    */
  def validateClient(request: ValidatedImplicit): F[Boolean]

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
}
