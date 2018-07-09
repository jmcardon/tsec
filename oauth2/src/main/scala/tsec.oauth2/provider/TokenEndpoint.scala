package tsec.oauth2.provider

import cats.data.EitherT
import cats.effect.Sync
import tsec.oauth2.provider.ValidatedRequest._
import tsec.oauth2.provider.grantHandler.GrantType.ClientCrendentials
import tsec.oauth2.provider.grantHandler._

object TokenEndpoint {
  def apply[F[_], U](
      dataHandler: DataHandlers[F, U]
  ): TokenEndpoint[F, U] = new TokenEndpoint[F, U](dataHandler)
}

class TokenEndpoint[F[_], U](dataHandler: DataHandlers[F, U]) {
  val passwordWithClientCredHandler: Option[PasswordWithClientCredGrantHandler[F, U]] =
    dataHandler.passwordWithClientCredHandler.map(x => new PasswordWithClientCredGrantHandler[F, U](x))
  val passwordNoClientCredHandler: Option[PasswordNoClientCredGrantHandler[F, U]] =
    dataHandler.passwordNoClientCredHandler.map(x => new PasswordNoClientCredGrantHandler[F, U](x))
  val clientCredentialsHandler: Option[ClientCredentialsGrantHandler[F, U]] =
    dataHandler.clientCredentialsHandler.map(x => new ClientCredentialsGrantHandler[F, U](x))
  val implicitHandler: Option[ImplicitGrantHandler[F, U]] =
    dataHandler.implicitHandler.map(x => new ImplicitGrantHandler[F, U](x))
  val refreshTokenHandler: Option[RefreshTokenGrantHandler[F, U]] =
    dataHandler.refreshTokenHandler.map(x => new RefreshTokenGrantHandler[F, U](x))
  val authorizationCodeHandler: Option[AuthorizationCodeGrantHandler[F, U]] =
    dataHandler.authorizationCodeHandler.map(x => new AuthorizationCodeGrantHandler[F, U](x))

  def authorize(
      headers: Map[String, Seq[String]],
      params: Map[String, Seq[String]],
      isClientCredRequiredForPasswordGrantType: Boolean = true
  )(implicit F: Sync[F]): EitherT[F, OAuthError, GrantHandlerResult[U]] =
    for {
      header <- EitherT.fromEither[F](
        params.get(GrantType.header).flatMap(_.headOption).toRight(InvalidRequest("Missing grant type"))
      )
      grantType <- EitherT.fromEither(
        GrantType.strToGrantType
          .get(header.toLowerCase)
          .toRight(UnsupportedGrantType(s"unsupported grant type: $header"))
      )
      res <- grantType match {
        case GrantType.AuthorizationCode =>
          for {
            handler <- EitherT
              .fromOption[F](authorizationCodeHandler, UnsupportedGrantType(s"No dataHandler defined for $grantType"))
            req <- EitherT.fromEither(createValidatedAuthorizationCode(headers, params))
            r   <- handler.handleRequest(req)
          } yield r
        case GrantType.RefreshToken =>
          for {
            handler <- EitherT
              .fromOption[F](refreshTokenHandler, UnsupportedGrantType(s"No dataHandler defined for $grantType"))
            req <- EitherT.fromEither(createValidatedRefreshToken(headers, params))
            r   <- handler.handleRequest(req)
          } yield r
        case ClientCrendentials =>
          for {
            handler <- EitherT
              .fromOption[F](clientCredentialsHandler, UnsupportedGrantType(s"No dataHandler defined for $grantType"))
            req <- EitherT.fromEither(createValidatedClientCredentials(headers, params))
            r   <- handler.handleRequest(req)
          } yield r
        case GrantType.Password =>
          if (isClientCredRequiredForPasswordGrantType)
            for {
              handler <- EitherT.fromOption[F](
                passwordWithClientCredHandler,
                UnsupportedGrantType(s"No dataHandler defined for $grantType")
              )
              req <- EitherT.fromEither(createValidatedPasswordWithClientCred(headers, params))
              r   <- handler.handleRequest(req)
            } yield r
          else
            for {
              handler <- EitherT.fromOption[F](
                passwordNoClientCredHandler,
                UnsupportedGrantType(s"No dataHandler defined for $grantType")
              )
              req <- EitherT.fromEither(createValidatedPasswordNoClientCred(params))
              r   <- handler.handleRequest(req)
            } yield r
        case GrantType.Implicit =>
          for {
            handler <- EitherT
              .fromOption[F](implicitHandler, UnsupportedGrantType(s"No dataHandler defined for $grantType"))
            req <- EitherT.fromEither(createValidatedImplicit(headers, params))
            r   <- handler.handleRequest(req)
          } yield r
      }
    } yield res
//
//  def authorize[A](req: A)(
//    implicit F: Sync[F],
//    x: GrantHandler.Aux[F, U, A]
//  ): EitherT[F, OAuthError, GrantHandlerResult[U]] = x.handleRequest(req)
}

final case class DataHandlers[F[_], U](
    passwordWithClientCredHandler: Option[PasswordWithClientCredHandler[F, U]],
    passwordNoClientCredHandler: Option[PasswordNoClientCredHandler[F, U]],
    clientCredentialsHandler: Option[ClientCredentialsHandler[F, U]],
    implicitHandler: Option[ImplicitHandler[F, U]],
    refreshTokenHandler: Option[RefreshTokenHandler[F, U]],
    authorizationCodeHandler: Option[AuthorizationCodeHandler[F, U]]
)
