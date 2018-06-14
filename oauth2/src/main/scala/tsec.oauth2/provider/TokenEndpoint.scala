package tsec.oauth2.provider

import cats.data.EitherT
import cats.effect.Sync

class TokenEndpoint[F[_]] {
  def handleRequest[U](
      request: AuthorizationRequest,
      handler: AuthorizationHandler[F, U],
      isClientCredRequiredForPasswordGrantType: Boolean
  )(implicit F: Sync[F]): EitherT[F, OAuthError, GrantHandlerResult[U]] =
    for {
      grantType <- EitherT.fromEither[F](request.grantType(isClientCredRequiredForPasswordGrantType))
      grantHandler = GrantHandler[F](grantType, isClientCredRequiredForPasswordGrantType)
      r            <- grantHandler.handleRequest(request, handler)
    } yield r
}
