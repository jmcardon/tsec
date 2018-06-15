package tsec.oauth2.provider

import cats.implicits._
import ca.mrvisser.sealerate
import cats.data.EitherT
import cats.effect.Sync
import tsec.oauth2.provider.GrantType._

import scala.concurrent.duration.FiniteDuration

sealed abstract class GrantType extends Product with Serializable {
  def name: String
}
object GrantType {
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
      request: AuthorizationRequest,
      authorizationHandler: AuthorizationHandler[F, U]
  )(implicit F: Sync[F]): EitherT[F, OAuthError, GrantHandlerResult[U]]

  protected def getClientCredential[U](
      request: AuthorizationRequest,
      handler: AuthorizationHandler[F, U]
  )(implicit F: Sync[F]): EitherT[F, OAuthError, ClientCredential] =
    for {
      credential <- EitherT.fromEither[F](request.parseClientCredential)
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
          shouldRefreshAccessToken(token).flatMap { shouldRefresh =>
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
    } yield createGrantHandlerResult(authInfo, t, expiresIn)

  protected def shouldRefreshAccessToken(accessToken: AccessToken)(implicit F: Sync[F]): F[Boolean] =
    accessToken.isExpired

  protected def createGrantHandlerResult[U](
      authInfo: AuthInfo[U],
      accessToken: AccessToken,
      expiresIn: Option[FiniteDuration]
  ): GrantHandlerResult[U] =
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

object GrantHandler {
  def apply[F[_]](grantType: GrantType, isClientCredRequiredForPasswordGrantType: Boolean): GrantHandler[F] =
    grantType match {
      case AuthorizationCode =>
        new AuthorizationCode[F]
      case RefreshToken =>
        new RefreshToken[F]
      case ClientCrendentials =>
        new ClientCredentials[F]
      case Password =>
        if (isClientCredRequiredForPasswordGrantType)
          new PasswordWithClientCred[F]
        else
          new PasswordNoClientCred[F]
      case Implicit =>
        new Implicit[F]
    }

  class RefreshToken[F[_]] extends GrantHandler[F] {
    def handleRequest[U](
        request: AuthorizationRequest,
        handler: AuthorizationHandler[F, U]
    )(implicit F: Sync[F]): EitherT[F, OAuthError, GrantHandlerResult[U]] =
      for {
        credential <- getClientCredential(request, handler)
        refreshToken <- EitherT.fromEither[F](
          request.params
            .get("refresh_token")
            .flatMap(_.headOption)
            .toRight(InvalidRequest("missing refresh_token param"))
        )
        auth <- EitherT(
          handler
            .findAuthInfoByRefreshToken(refreshToken)
            .map(_.toRight(InvalidGrant("Authorized information is not found by the refresh token")))
        )
        _ <- EitherT.cond[F](auth.clientId.contains(credential.clientId), (), InvalidClient("invalid clientId"))
        token <- EitherT(
          handler
            .refreshAccessToken(auth, refreshToken)
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
  class PasswordWithClientCred[F[_]] extends GrantHandler[F] {
    def handleRequest[U](
        request: AuthorizationRequest,
        handler: AuthorizationHandler[F, U]
    )(implicit F: Sync[F]): EitherT[F, OAuthError, GrantHandlerResult[U]] =
      for {
        credential <- getClientCredential(request, handler)
        password <- EitherT.fromEither[F](
          request.params.get("password").flatMap(_.headOption).toRight(InvalidRequest("missing password param"))
        )
        username <- EitherT.fromEither[F](
          request.params.get("username").flatMap(_.headOption).toRight(InvalidRequest("missing username param"))
        )
        user <- EitherT(
          handler.findUser(Some(credential), request).map(_.toRight(InvalidGrant("username or password is incorrect")))
        )
        authInfo = AuthInfo(user, Some(credential.clientId), request.scope, None)
        grantResult <- EitherT(
          issueAccessToken(handler, authInfo).attempt
            .map(_.leftMap(t => FailedToIssueAccessToken(t.getMessage): OAuthError))
        )
      } yield grantResult
  }

  class PasswordNoClientCred[F[_]] extends GrantHandler[F] {
    def handleRequest[U](
        request: AuthorizationRequest,
        handler: AuthorizationHandler[F, U]
    )(implicit F: Sync[F]): EitherT[F, OAuthError, GrantHandlerResult[U]] =
      for {
        password <- EitherT.fromEither[F](
          request.params.get("password").flatMap(_.headOption).toRight(InvalidRequest("missing password param"))
        )
        username <- EitherT.fromEither[F](
          request.params.get("username").flatMap(_.headOption).toRight(InvalidRequest("missing username param"))
        )
        user <- EitherT(
          handler.findUser(None, request).map(_.toRight(InvalidGrant("username or password is incorrect")))
        )
        scope    = request.scope
        authInfo = AuthInfo(user, None, scope, None)
        grantResult <- EitherT(
          issueAccessToken(handler, authInfo).attempt
            .map(_.leftMap(t => FailedToIssueAccessToken(t.getMessage): OAuthError))
        )
      } yield grantResult
  }

  class ClientCredentials[F[_]] extends GrantHandler[F] {
    def handleRequest[U](
        request: AuthorizationRequest,
        handler: AuthorizationHandler[F, U]
    )(implicit F: Sync[F]): EitherT[F, OAuthError, GrantHandlerResult[U]] =
      for {
        credential <- getClientCredential(request, handler)
        user <- EitherT(
          handler
            .findUser(Some(credential), request)
            .map(_.toRight(InvalidGrant("client_id or client_secret or scope is incorrect")))
        )
        authInfo = AuthInfo(user, Some(credential.clientId), request.scope, None)
        grantResult <- EitherT(
          issueAccessToken(handler, authInfo).attempt
            .map(_.leftMap(t => FailedToIssueAccessToken(t.getMessage): OAuthError))
        )
      } yield grantResult
  }

  class AuthorizationCode[F[_]] extends GrantHandler[F] {
    def handleRequest[U](
        request: AuthorizationRequest,
        handler: AuthorizationHandler[F, U]
    )(implicit F: Sync[F]): EitherT[F, OAuthError, GrantHandlerResult[U]] =
      for {
        credential <- getClientCredential(request, handler)
        code <- EitherT.fromEither[F](
          request.params.get("code").flatMap(_.headOption).toRight(InvalidRequest("missing code param"))
        )
        auth <- EitherT(
          handler
            .findAuthInfoByCode(code)
            .map(_.toRight(InvalidGrant("Authorized information is not found by the code")))
        )
        _ <- EitherT.cond[F](auth.clientId.contains(credential.clientId), (), InvalidClient("invalid clientId"))
        redirectUri = request.params.get("redirect_uri").flatMap(_.headOption)
        _ <- EitherT.cond[F](
          auth.redirectUri.isEmpty || (auth.redirectUri.isDefined && auth.redirectUri == redirectUri),
          (),
          RedirectUriMismatch
        )
        grantResult <- EitherT(
          issueAccessToken(handler, auth).attempt
            .map(_.leftMap(t => FailedToIssueAccessToken(t.getMessage): OAuthError))
        )
        _ <- EitherT(
          handler.deleteAuthCode(code).attempt.map(_.leftMap(t => FailedToDeleteAuthCode(t.getMessage): OAuthError))
        )
      } yield grantResult
  }

  class Implicit[F[_]] extends GrantHandler[F] {
    def handleRequest[U](
        request: AuthorizationRequest,
        handler: AuthorizationHandler[F, U]
    )(implicit F: Sync[F]): EitherT[F, OAuthError, GrantHandlerResult[U]] =
      for {
        credential <- getClientCredential(request, handler)
        user <- EitherT(
          handler.findUser(Some(credential), request).map(_.toRight(InvalidGrant("user cannot be authenticated")))
        )
        grantResult <- EitherT(
          issueAccessToken(handler, AuthInfo(user, Some(credential.clientId), request.scope, None)).attempt
            .map(_.leftMap(t => FailedToIssueAccessToken(t.getMessage): OAuthError))
        )
      } yield grantResult

    /**
      * Implicit grant doesn't support refresh token
      */
    protected override def shouldRefreshAccessToken(accessToken: AccessToken)(implicit F: Sync[F]): F[Boolean] =
      F.pure(false)

    /**
      * Implicit grant must not return refresh token
      */
    protected override def createGrantHandlerResult[U](
        authInfo: AuthInfo[U],
        accessToken: AccessToken,
        expiresIn: Option[FiniteDuration]
    ) =
      super.createGrantHandlerResult(authInfo, accessToken, expiresIn).copy(refreshToken = None)
  }

//  val strToGrantHandler: Map[String, GrantHandler] = sealerate.values[GrantHandler].map(g => g.name -> g).toMap
}
