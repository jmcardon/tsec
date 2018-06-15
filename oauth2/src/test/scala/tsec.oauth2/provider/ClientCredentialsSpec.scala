package tsec.oauth2.provider

import java.time.Instant

import cats.effect.IO
import org.scalatest.Matchers._
import org.scalatest._
import tsec.oauth2.provider.GrantHandler.ClientCredentials

import scala.concurrent.duration._

class ClientCredentialsSpec extends FlatSpec with OptionValues {

  val handler = new ClientCredentials[IO]

  it should "handle request" in {
    val request = new AuthorizationRequest(
      Map(),
      Map("client_id" -> Seq("clientId1"), "client_secret" -> Seq("clientSecret1"), "scope" -> Seq("all"))
    )
    val f = handler.handleRequest(
      request,
      new MockDataHandler() {
        override def validateClient(credential: ClientCredential, request: AuthorizationRequest): IO[Boolean] = IO.pure(true)

        override def findUser(
            maybeClientCredential: Option[ClientCredential],
            request: AuthorizationRequest
        ): IO[Option[MockUser]] = IO.pure(Some(MockUser(10000, "username")))

        override def createAccessToken(authInfo: AuthInfo[MockUser]): IO[AccessToken] =
          IO.pure(AccessToken("token1", None, Some("all"), Some(3600 seconds), Instant.now()))
      }
    )
    val result = f.value.unsafeRunSync().toOption.get

    result.tokenType should be("Bearer")
    result.accessToken should be("token1")
    result.expiresIn.value.toMillis should (be <= 3600L and be > 3595L)
    result.refreshToken should be(None)
    result.scope should be(Some("all"))
  }
}
