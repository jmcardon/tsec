package tsec.oauth2.provider

import cats.data.EitherT
import cats.effect.Sync

object TokenEndpoint{
  def create[F[_]](headers: Map[String, Seq[String]], isClientCredRequiredForPasswordGrantType: Boolean, params: Map[String, Seq[String]]): Either[OAuthError, TokenEndpoint[F]] =
    validateRequest(headers, isClientCredRequiredForPasswordGrantType, params).map(req => new TokenEndpoint[F](req))

  private[TokenEndpoint] def validateRequest(headers: Map[String, Seq[String]], isClientCredRequiredForPasswordGrantType: Boolean, params: Map[String, Seq[String]]): Either[OAuthError, ValidatedRequest] = for {
    header <- params.get(GrantType.header).flatMap(_.headOption).toRight(InvalidRequest("Missing grant type"))
    grantType <- GrantType.strToGrantType
      .get(header.toLowerCase)
      .toRight(UnsupportedGrantType(s"unsupported grant type: $header"))
    req <- ValidatedRequest.create(grantType, isClientCredRequiredForPasswordGrantType, headers, params)
  } yield req
}

class TokenEndpoint[F[_]](req: ValidatedRequest) {
  def handleRequest[U](handler: AuthorizationHandler[F, U])(implicit F: Sync[F]): EitherT[F, OAuthError, GrantHandlerResult[U]] = GrantHandler[F](req).handleRequest(handler)
}
