package tsec.oauth2.provider

import java.time.Instant

import cats.effect.IO
import cats.syntax.either._
import org.scalatest.Matchers._
import org.scalatest._
import tsec.oauth2.provider.ValidatedRequest.ValidatedAuthorizationCode
import tsec.oauth2.provider.grantHandler.AuthorizationCodeGrantHandler
import tsec.oauth2.provider.grantHandler.AuthorizationCodeHandler

import scala.concurrent.duration._

class AuthorizationCodeGrantHandlerSpec extends FlatSpec with OptionValues {

  it should "handle request" in {
    var codeDeleted: Boolean = false
    val dataHandler = new AuthorizationCodeHandler[IO, MockUser] {
      override def validateClient(request: ValidatedAuthorizationCode): IO[Boolean] =
        IO.pure(true)
      override def findAuthInfoByCode(code: String): IO[Option[AuthInfo[MockUser]]] =
        IO.pure(
          Some(
            AuthInfo(
              user = MockUser(10000, "username"),
              clientId = Some("clientId1"),
              scope = Some("all"),
              redirectUri = Some("http://example.com/")
            )
          )
        )

      override def createAccessToken(authInfo: AuthInfo[MockUser]): IO[AccessToken] =
        IO.pure(AccessToken("token1", Some("refreshToken1"), Some("all"), Some(3600 seconds),Instant.now()))

      override def deleteAuthCode(code: String): IO[Unit] = {
        Thread.sleep(300)
        codeDeleted = true
        IO.pure(())
      }

      override def getStoredAccessToken(authInfo: AuthInfo[MockUser]): IO[Option[AccessToken]] = IO.pure(None)
      override def refreshAccessToken(authInfo: AuthInfo[MockUser], refreshToken: String): IO[AccessToken] = IO.pure(AccessToken("", Some(""), Some(""), Some(0 seconds), Instant.now()))
    }
    val handler = new AuthorizationCodeGrantHandler[IO, MockUser](dataHandler)

    val f = handler.handleRequest(
      ValidatedAuthorizationCode(ClientCredential("clientId1", Some("ClientSecret1")), "code1", None, Some("http://example.com/"))
    )

    val result = f.value.unsafeRunSync().toOption.get
    codeDeleted shouldBe true
    result.tokenType shouldBe "Bearer"
    result.accessToken shouldBe "token1"
    result.expiresIn.value.toMillis should (be <= 3600L and be > 3595L)
    result.refreshToken shouldBe Some("refreshToken1")
    result.scope shouldBe Some("all")
  }

  it should "handle request if redirectUrl is none" in {
    val dataHandler = new AuthorizationCodeHandler[IO, MockUser] {
      override def validateClient(request: ValidatedAuthorizationCode): IO[Boolean] =
        IO.pure(true)
      override def findAuthInfoByCode(code: String): IO[Option[AuthInfo[MockUser]]] =
        IO.pure(
          Some(
            AuthInfo(
              user = MockUser(10000, "username"),
              clientId = Some("clientId1"),
              scope = Some("all"),
              redirectUri = None
            )
          )
        )

      override def createAccessToken(authInfo: AuthInfo[MockUser]): IO[AccessToken] =
        IO.pure(AccessToken("token1", Some("refreshToken1"), Some("all"), Some(3600 seconds), Instant.now()))
      override def deleteAuthCode(code: String): IO[Unit] = IO.pure(())
      override def getStoredAccessToken(authInfo: AuthInfo[MockUser]): IO[Option[AccessToken]] = IO.pure(None)
      override def refreshAccessToken(authInfo: AuthInfo[MockUser], refreshToken: String): IO[AccessToken] = IO.pure(AccessToken("", Some(""), Some(""), Some(0 seconds), Instant.now()))
    }
    val handler = new AuthorizationCodeGrantHandler[IO, MockUser](dataHandler)
    val f = handler.handleRequest(
      ValidatedAuthorizationCode(ClientCredential("clientId1", Some("ClientSecret1")), "code1", None, None)
    )

    val result = f.value.unsafeRunSync().toOption.get
    result.tokenType shouldBe "Bearer"
    result.accessToken shouldBe "token1"
    result.expiresIn.value.toMillis should (be <= 3600L and be > 2595L)
    result.refreshToken shouldBe Some("refreshToken1")
    result.scope shouldBe Some("all")
  }

  it should "return a Failure IO" in {
    val dataHandler = new AuthorizationCodeHandler[IO, MockUser] {
      override def validateClient(request: ValidatedAuthorizationCode): IO[Boolean] = IO.pure(true)

      override def findAuthInfoByCode(code: String): IO[Option[AuthInfo[MockUser]]] =
        IO.pure(
          Some(
            AuthInfo(
              user = MockUser(10000, "username"),
              clientId = Some("clientId1"),
              scope = Some("all"),
              redirectUri = Some("http://example.com/")
            )
          )
        )

      override def createAccessToken(authInfo: AuthInfo[MockUser]): IO[AccessToken] =
        IO.pure(AccessToken("token1", Some("refreshToken1"), Some("all"), Some(3600 seconds), Instant.now()))

      override def deleteAuthCode(code: String): IO[Unit] =
        IO.raiseError(new Exception("fail"))
      override def getStoredAccessToken(authInfo: AuthInfo[MockUser]): IO[Option[AccessToken]] = IO.pure(None)
      override def refreshAccessToken(authInfo: AuthInfo[MockUser], refreshToken: String): IO[AccessToken] = IO.pure(AccessToken("", Some(""), Some(""), Some(0 seconds), Instant.now()))
    }
    val handler = new AuthorizationCodeGrantHandler[IO, MockUser](dataHandler)
    val f = handler.handleRequest(
      ValidatedAuthorizationCode(ClientCredential("clientId1", Some("ClientSecret1")), "code1", None, Some("http://example.com/"))
    )

    val result = f.value.unsafeRunSync()
    result shouldBe(Left(FailedToDeleteAuthCode("fail")))
  }
}
