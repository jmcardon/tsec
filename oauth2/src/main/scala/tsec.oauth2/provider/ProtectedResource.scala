package tsec.oauth2.provider

import cats.data.EitherT
import cats.effect.IO

object ProtectedResource {
  val fetchers = List(AuthHeader, RequestParameter)

  def handleRequest[U](
      request: ProtectedResourceRequest,
      handler: ProtectedResourceHandler[U]
  ): IO[Either[OAuthError, AuthInfo[U]]] = {
    val res: EitherT[IO, OAuthError, AuthInfo[U]] = for {
      result <- EitherT.fromEither[IO](
        fetchers
          .find { fetcher =>
            fetcher.matches(request)
          }
          .toRight(InvalidRequest("Access token is not found"))
          .flatMap(x => x.fetch(request))
      )
      token <- EitherT(
        handler.findAccessToken(result.token).map(_.toRight[OAuthError](InvalidToken("The access token is not found")))
      )
      _ <- EitherT.cond[IO](!token.isExpired, (), ExpiredToken)
      authInfo <- EitherT(
        handler.findAuthInfoByAccessToken(token).map(_.toRight[OAuthError](InvalidToken("The access token is invalid")))
      )
    } yield authInfo

    res.value
  }
}
