package tsec.oauth2.provider

import java.time.Instant

import cats.effect.IO

import scala.concurrent.duration._

class MockDataHandler extends DataHandler[IO, MockUser] {

  override def validateClient(maybeClientCredential: ClientCredential, request: AuthorizationRequest): IO[Boolean] =
    IO.pure(false)

  override def findUser(
      maybeClientCredential: Option[ClientCredential],
      request: AuthorizationRequest
  ): IO[Option[MockUser]] = IO.pure(None)

  override def createAccessToken(authInfo: AuthInfo[MockUser]): IO[AccessToken] =
    IO.pure(AccessToken("", Some(""), Some(""), Some(0 seconds), Instant.now()))

  override def findAuthInfoByCode(code: String): IO[Option[AuthInfo[MockUser]]] = IO.pure(None)

  override def findAuthInfoByRefreshToken(refreshToken: String): IO[Option[AuthInfo[MockUser]]] = IO.pure(None)

  override def findAccessToken(token: String): IO[Option[AccessToken]] = IO.pure(None)

  override def findAuthInfoByAccessToken(accessToken: AccessToken): IO[Option[AuthInfo[MockUser]]] = IO.pure(None)

  override def getStoredAccessToken(authInfo: AuthInfo[MockUser]): IO[Option[AccessToken]] = IO.pure(None)

  override def refreshAccessToken(authInfo: AuthInfo[MockUser], refreshToken: String): IO[AccessToken] =
    IO.pure(AccessToken("", Some(""), Some(""), Some(0 seconds), Instant.now()))

  override def deleteAuthCode(code: String): IO[Unit] = IO.pure(Unit)
}

case class MockUser(id: Long, name: String)
