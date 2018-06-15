package tsec.oauth2.provider

import java.time.Instant

import cats.effect.IO
import org.scalatest.{FlatSpec, OptionValues}
import org.scalatest.Matchers._
import tsec.oauth2.provider.GrantHandler.RefreshToken

import scala.concurrent.duration._

class RefreshTokenSpec extends FlatSpec with OptionValues {

  val handler = new RefreshToken[IO]

  it should "handle request" in {
    val request = new AuthorizationRequest(
      Map(),
      Map(
        "client_id"     -> Seq("clientId1"),
        "clinet_secret" -> Seq("clientSecret1"),
        "refresh_token" -> Seq("refreshToken1")
      )
    )
    val f = handler.handleRequest(
      request,
      new MockDataHandler() {

        override def validateClient(maybeClientCredential: ClientCredential, request: AuthorizationRequest): IO[Boolean] = IO.pure(true)

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

      }
    )
    val result = f.value.unsafeRunSync().toOption.get

    result.tokenType should be("Bearer")
    result.accessToken should be("token1")
    result.expiresIn.value.toMillis should (be <= 3600L and be > 3595L)
    result.refreshToken should be(Some("refreshToken1"))
    result.scope should be(None)
  }
}
