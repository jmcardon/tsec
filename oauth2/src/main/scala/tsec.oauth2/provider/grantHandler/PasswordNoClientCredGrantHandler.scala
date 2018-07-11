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
      user <- EitherT[F, OAuthError, U](
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
}
