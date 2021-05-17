package tsec.oauth2.provider

import java.time.Instant

import cats.effect.IO
import cats.syntax.either._
import org.scalatest.OptionValues
import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers._
import tsec.oauth2.provider.ValidatedRequest.ValidatedRefreshToken
import tsec.oauth2.provider.grantHandler.RefreshTokenGrantHandler
import tsec.oauth2.provider.grantHandler.RefreshTokenHandler
import cats.effect.unsafe.implicits.global

import scala.concurrent.duration._

class RefreshTokenGrantHandlerSpec extends AnyFlatSpec with OptionValues {

  it should "handle request" in {
    val dataHandler = new RefreshTokenHandler[IO, MockUser] {

      override def validateClient(request: ValidatedRefreshToken): IO[Boolean] = IO.pure(true)

      override def findAuthInfoByRefreshToken(refreshToken: String): IO[Option[AuthInfo[MockUser]]] =
        IO.pure(
          Some(
            AuthInfo(
              user = MockUser(10000, "username"),
              clientId = Some("clientId1"),
              scope = None,
              redirectUri = None
            )
          )
        )

      override def refreshAccessToken(authInfo: AuthInfo[MockUser], refreshToken: String): IO[AccessToken] =
        IO.pure(AccessToken("token1", Some(refreshToken), None, Some(3600 seconds), Instant.now()))
      override def createAccessToken(authInfo: AuthInfo[MockUser]): IO[AccessToken] = ???
      override def getStoredAccessToken(authInfo: AuthInfo[MockUser]): IO[Option[AccessToken]] = ???
    }
    val handler = new RefreshTokenGrantHandler[IO, MockUser](dataHandler)

    val f = handler.handleRequest(
      ValidatedRefreshToken(ClientCredential("clientId1", Some("ClientSecret1")), "refreshToken1", Some("all"))
    )
    val result = f.value.unsafeRunSync().toOption.get

    result.tokenType should be("Bearer")
    result.accessToken should be("token1")
    result.expiresIn.value.toMillis should (be <= 3600L and be > 3595L)
    result.refreshToken should be(Some("refreshToken1"))
    result.scope should be(None)
  }
}
