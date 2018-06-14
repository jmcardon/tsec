package tsec.oauth2.provider

import cats.effect.IO
import org.scalatest._
import org.scalatest.Matchers._
import scala.concurrent.duration._
import tsec.oauth2.provider.GrantHandler.PasswordNoClientCred
import tsec.oauth2.provider.GrantHandler.PasswordWithClientCred

class PasswordSpec extends FlatSpec with OptionValues {

  val passwordClientCredReq   = new PasswordWithClientCred[IO]
  val passwordNoClientCredReq = new PasswordNoClientCred[IO]

  "Password when client credential required" should "handle request" in handlesRequest(
    passwordClientCredReq,
    Map("client_id" -> Seq("clientId1"), "client_secret" -> Seq("clientSecret1"))
  )
  "Password when client credential not required" should "handle request" in handlesRequest(
    passwordNoClientCredReq,
    Map.empty
  )

  def handlesRequest(password: GrantHandler[IO], params: Map[String, Seq[String]]) = {
    val request = new AuthorizationRequest(
      Map(),
      params ++ Map("username" -> Seq("user"), "password" -> Seq("pass"), "scope" -> Seq("all"))
    )
    val f = password.handleRequest(
      request,
      new MockDataHandler() {
        override def validateClient(maybeClientCredential: ClientCredential, request: AuthorizationRequest): IO[Boolean] = IO.pure(true)

        override def findUser(
            maybeClientCredential: Option[ClientCredential],
            request: AuthorizationRequest
        ): IO[Option[MockUser]] = IO.pure(Some(MockUser(10000, "username")))

        override def createAccessToken(authInfo: AuthInfo[MockUser]): IO[AccessToken] =
          IO.pure(AccessToken("token1", Some("refreshToken1"), Some("all"), Some(3600 seconds), new java.util.Date()))

      }
    )

    val result = f.value.unsafeRunSync().toOption.get
    result.tokenType should be("Bearer")
    result.accessToken should be("token1")
    result.expiresIn.value.toMillis should (be <= 3600L and be > 3595L)
    result.refreshToken should be(Some("refreshToken1"))
    result.scope should be(Some("all"))
  }
}
