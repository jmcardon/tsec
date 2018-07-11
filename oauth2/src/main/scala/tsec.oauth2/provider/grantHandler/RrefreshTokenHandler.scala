package tsec.oauth2.provider
package grantHandler

import cats.data.EitherT
import cats.effect.Sync
import cats.implicits._
import tsec.oauth2.provider.ValidatedRequest._

class RefreshTokenGrantHandler[F[_], U](handler: RefreshTokenHandler[F, U]) extends GrantHandler[F, U] {
  type A = ValidatedRefreshToken
  def handleRequest(req: ValidatedRefreshToken)(implicit F: Sync[F]): EitherT[F, OAuthError, GrantHandlerResult[U]] =
    for {
      _ <- EitherT[F, OAuthError, Unit](
        handler
          .validateClient(req)
          .map(
            isValid => Either.cond(isValid, (), InvalidClient("Invalid client or client is not authorized"): OAuthError)
          )
      )
      auth <- EitherT[F, OAuthError, AuthInfo[U]](
        handler
          .findAuthInfoByRefreshToken(req.refreshToken)
          .map(_.toRight(InvalidGrant("Authorized information is not found by the refresh token")))
      )
      _ <- EitherT
        .cond[F](auth.clientId.contains(req.clientCredential.clientId), (), InvalidClient("invalid clientId"))
      token <- EitherT(
        handler
          .refreshAccessToken(auth, req.refreshToken)
          .attempt
          .map(_.leftMap(t => RefreshTokenFailed(t.getMessage): OAuthError))
      )
      grantResult <- EitherT(
        token.expiresIn
          .map(GrantHandler.createGrantHandlerResult(auth, token, _))
          .attempt
          .map(_.leftMap(t => RefreshTokenFailed(t.getMessage): OAuthError))
      )
    } yield grantResult
}

trait RefreshTokenHandler[F[_], U] {

  /**
    * Verify proper client with parameters for issue an access token.
    * Note that per the OAuth Specification, a Client may be valid if it only contains a client ID but no client
    * secret (common with Public Clients). However, if the registered client has a client secret value the specification
    * requires that a client secret must always be provided and verified for that client ID.
    *
    * @param request Request sent by client.
    * @return true if request is a regular client, false if request is a illegal client.
    */
  def validateClient(request: ValidatedRefreshToken): F[Boolean]

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

  /**
    * Find authorized information by refresh token.
    *
    * If you don't support Refresh Token Grant then doesn't need implementing.
    *
    * @param refreshToken Client sends refresh token which is created by system.
    * @return Return authorized information that matched the refresh token.
    */
  def findAuthInfoByRefreshToken(refreshToken: String): F[Option[AuthInfo[U]]]
}
