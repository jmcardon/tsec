package tsec.oauth2.provider

import java.nio.charset.StandardCharsets

import cats.implicits._
import ca.mrvisser.sealerate
import cats.data.EitherT
import cats.effect.Sync
import tsec.oauth2.provider.GrantType._
import tsec.common._
import tsec.oauth2.provider.ValidatedRequest._

import scala.collection.immutable.TreeMap
import scala.concurrent.duration.FiniteDuration
import scala.util.Try

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

  val strToGrantType = sealerate.values[GrantType].map(g => g.name -> g).toMap
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

sealed trait GrantHandler[F[_]] {
  def handleRequest[U](
                        authorizationHandler: AuthorizationHandler[F, U]
  )(implicit F: Sync[F]): EitherT[F, OAuthError, GrantHandlerResult[U]]

  protected def getClientCredential[U](
                                        credential: ClientCredential,
                                        request: ValidatedRequest,
                                        handler: AuthorizationHandler[F, U]
  )(implicit F: Sync[F]): EitherT[F, OAuthError, ClientCredential] =
    for {
      _ <- EitherT(
        handler
          .validateClient(credential, request)
          .map(
            isValid => Either.cond(isValid, (), InvalidClient("Invalid client or client is not authorized"): OAuthError)
          )
      )
    } yield credential

  /**
    * Returns valid access token.
    */
  protected def issueAccessToken[U](
      handler: AuthorizationHandler[F, U],
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
  def apply[F[_]](req: ValidatedRequest): GrantHandler[F] =
    req match {
      case r: ValidatedAuthorizationCode =>
        new AuthorizationCode[F](r)
      case r: ValidatedRefreshToken =>
        new RefreshToken[F](r)
      case r: ValidatedClientCrendentials =>
        new ClientCredentials[F](r)
      case r: ValidatedPasswordWithClientCred =>
        new PasswordWithClientCred[F](r)
      case r: ValidatedPasswordNoClientCred =>
        new PasswordNoClientCred[F](r)
      case r: ValidatedImplicit =>
        new Implicit[F](r)
    }

  def createGrantHandlerResult[U](
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

  class RefreshToken[F[_]](req: ValidatedRefreshToken) extends GrantHandler[F] {
    def handleRequest[U](handler: AuthorizationHandler[F, U]
    )(implicit F: Sync[F]): EitherT[F, OAuthError, GrantHandlerResult[U]] =
      for {
        auth <- EitherT(
          handler
            .findAuthInfoByRefreshToken(req.refreshToken)
            .map(_.toRight(InvalidGrant("Authorized information is not found by the refresh token")))
        )
        _ <- EitherT.cond[F](auth.clientId.contains(req.clientCredential.clientId), (), InvalidClient("invalid clientId"))
        token <- EitherT(
          handler
            .refreshAccessToken(auth, req.refreshToken)
            .attempt
            .map(_.leftMap(t => RefreshTokenFailed(t.getMessage): OAuthError))
        )
        grantResult <- EitherT(
          token.expiresIn
            .map(createGrantHandlerResult(auth, token, _))
            .attempt
            .map(_.leftMap(t => RefreshTokenFailed(t.getMessage): OAuthError))
        )
      } yield grantResult
  }

  /**
    * Per the OAuth2 specification, client credentials are required for all grant types except password, where it is up
    * to the authorization provider whether to make them required or not.
    */
  class PasswordWithClientCred[F[_]](req: ValidatedPasswordWithClientCred) extends GrantHandler[F] {
    def handleRequest[U](
                          handler: AuthorizationHandler[F, U]
    )(implicit F: Sync[F]): EitherT[F, OAuthError, GrantHandlerResult[U]] =
      for {
        user <- EitherT(
          handler.findUser(Some(req.clientCredential), req).map(_.toRight(InvalidGrant("username or password is incorrect")))
        )
        authInfo = AuthInfo(user, Some(req.clientCredential.clientId), req.scope, None)
        grantResult <- EitherT(
          issueAccessToken(handler, authInfo).attempt
            .map(_.leftMap(t => FailedToIssueAccessToken(t.getMessage): OAuthError))
        )
      } yield grantResult
  }

  class PasswordNoClientCred[F[_]](req: ValidatedPasswordNoClientCred) extends GrantHandler[F] {
    def handleRequest[U](
                          handler: AuthorizationHandler[F, U]
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

  class ClientCredentials[F[_]](req: ValidatedClientCrendentials) extends GrantHandler[F] {
    def handleRequest[U](handler: AuthorizationHandler[F, U]
    )(implicit F: Sync[F]): EitherT[F, OAuthError, GrantHandlerResult[U]] =
      for {
        user <- EitherT(
          handler
            .findUser(Some(req.clientCredential), req)
            .map(_.toRight(InvalidGrant("client_id or client_secret or scope is incorrect")))
        )
        authInfo = AuthInfo(user, Some(req.clientCredential.clientId), req.scope, None)
        grantResult <- EitherT(
          issueAccessToken(handler, authInfo).attempt
            .map(_.leftMap(t => FailedToIssueAccessToken(t.getMessage): OAuthError))
        )
      } yield grantResult
  }

  class AuthorizationCode[F[_]](req: ValidatedAuthorizationCode) extends GrantHandler[F] {
    def handleRequest[U](
                          handler: AuthorizationHandler[F, U]
    )(implicit F: Sync[F]): EitherT[F, OAuthError, GrantHandlerResult[U]] =
      for {
        auth <- EitherT(
          handler
            .findAuthInfoByCode(req.code)
            .map(_.toRight(InvalidGrant("Authorized information is not found by the code")))
        )
        _ <- EitherT.cond[F](auth.clientId.contains(req.clientCredential.clientId), (), InvalidClient("invalid clientId"))
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


  class Implicit[F[_]](req: ValidatedImplicit) extends GrantHandler[F] {
    def handleRequest[U](
                          handler: AuthorizationHandler[F, U]
    )(implicit F: Sync[F]): EitherT[F, OAuthError, GrantHandlerResult[U]] =
      for {
        user <- EitherT(
          handler.findUser(Some(req.clientCredential), req).map(_.toRight(InvalidGrant("user cannot be authenticated")))
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
}
