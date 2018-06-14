package tsec.oauth2.provider

import java.util.Date

import cats.effect.IO
import org.scalatest._
import org.scalatest.Matchers._
import org.scalatest.concurrent.ScalaFutures
import tsec.oauth2.provider.GrantHandler.Implicit

import scala.concurrent.duration._

class ImplicitSpec extends FlatSpec with ScalaFutures with OptionValues {
  val handler = new Implicit[IO]

  it should "grant access with valid user authentication" in handlesRequest("user", "pass", true)
  it should "not grant access with invalid user authentication" in handlesRequest("user", "wrong_pass", false)

  def handlesRequest(user: String, pass: String, ok: Boolean) = {
    val request = new AuthorizationRequest(
      Map(),
      Map("client_id" -> Seq("client"), "username" -> Seq(user), "password" -> Seq(pass), "scope" -> Seq("all"))
    )
    val f = handler.handleRequest(
      request,
      new MockDataHandler() {
        override def validateClient(maybeClientCredential: ClientCredential, request: AuthorizationRequest): IO[Boolean] = IO.pure(true)

        override def findUser(
            maybeClientCredential: Option[ClientCredential],
            request: AuthorizationRequest
        ): IO[Option[MockUser]] = {
          val result = for {
            user     <- request.params.get("username") if user.head == "user"
            password <- request.params.get("password") if password.head == "pass"
          } yield MockUser(10000, "username")
          IO.pure(result)
        }

        override def createAccessToken(authInfo: AuthInfo[MockUser]): IO[AccessToken] =
          IO.pure(AccessToken("token1", Some("refresh_token"), Some("all"), Some(3600 seconds), new Date()))

      }
    )

    if (ok) {
      val result = f.value.unsafeRunSync().toOption.get
      result.tokenType should be("Bearer")
      result.accessToken should be("token1")
      result.expiresIn.value.toMillis should (be <= 3600L and be > 3595L)
      result.refreshToken should be(None)
      result.scope should be(Some("all"))
    } else {
      val result = f.value.unsafeRunSync()
      result shouldBe Left(InvalidGrant("user cannot be authenticated"))
    }
  }
}
