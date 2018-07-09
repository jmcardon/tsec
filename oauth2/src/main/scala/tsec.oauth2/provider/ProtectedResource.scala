package tsec.oauth2.provider

import cats.implicits._
import cats.data.EitherT
import cats.effect.Sync

object ProtectedResource {
  def apply[F[_], U](handler: ProtectedResourceHandler[F, U]): ProtectedResource[F, U] = new ProtectedResource[F, U](handler)
}

class ProtectedResource[F[_], U](handler: ProtectedResourceHandler[F, U]) {
  val fetchers = AccessTokenFetcher.all

  def authorize(
      request: ProtectedResourceRequest
  )(implicit F: Sync[F]): EitherT[F, OAuthError, AuthInfo[U]] =
    for {
      result <- EitherT.fromEither[F](
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
      _ <- EitherT(token.isExpired.map(expired => Either.cond(!expired, (), ExpiredToken)))
      authInfo <- EitherT(
        handler.findAuthInfoByAccessToken(token).map(_.toRight[OAuthError](InvalidToken("The access token is invalid")))
      )
    } yield authInfo
}
