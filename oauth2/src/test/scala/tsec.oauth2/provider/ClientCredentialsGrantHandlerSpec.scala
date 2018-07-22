package tsec.oauth2.provider

import java.time.Instant

import cats.effect.IO
import cats.syntax.either._
import org.scalatest.Matchers._
import org.scalatest._
import tsec.oauth2.provider.ValidatedRequest.ValidatedClientCredentials
import tsec.oauth2.provider.grantHandler.ClientCredentialsGrantHandler
import tsec.oauth2.provider.grantHandler.ClientCredentialsHandler

import scala.concurrent.duration._

class ClientCredentialsGrantHandlerSpec extends FlatSpec with OptionValues {

  it should "handle request" in {
    val dataHandler = new ClientCredentialsHandler[IO, MockUser] {
      override def validateClient(request: ValidatedClientCredentials): IO[Boolean] = IO.pure(true)

      override def findUser(
                             request: ValidatedClientCredentials
                           ): IO[Option[MockUser]] = IO.pure(Some(MockUser(10000, "username")))

      override def createAccessToken(authInfo: AuthInfo[MockUser]): IO[AccessToken] =
        IO.pure(AccessToken("token1", None, Some("all"), Some(3600 seconds), Instant.now()))
      override def getStoredAccessToken(authInfo: AuthInfo[MockUser]): IO[Option[AccessToken]] = IO.pure(None)
      override def refreshAccessToken(authInfo: AuthInfo[MockUser], refreshToken: String): IO[AccessToken] = IO.pure(AccessToken("", Some(""), Some(""), Some(0 seconds), Instant.now()))
    }

    val handler = new ClientCredentialsGrantHandler[IO, MockUser](dataHandler)

    val f = handler.handleRequest(
      ValidatedClientCredentials(ClientCredential("clientId1", Some("ClientSecret1")), Some("all"))
    )
    val result = f.value.unsafeRunSync().toOption.get

    result.tokenType should be("Bearer")
    result.accessToken should be("token1")
    result.expiresIn.value.toMillis should (be <= 3600L and be > 3595L)
    result.refreshToken should be(None)
    result.scope should be(Some("all"))
  }
}
