package tsec.oauth2.provider

import java.time.Instant

import cats.effect.IO
import org.scalatest.Matchers._
import org.scalatest._
import org.scalatest.concurrent.ScalaFutures
import tsec.oauth2.provider.ValidatedRequest.ValidatedImplicit
import tsec.oauth2.provider.grantHandler.ImplicitGrantHandler
import tsec.oauth2.provider.grantHandler.ImplicitHandler

import scala.concurrent.duration._

class ImplicitSpec extends FlatSpec with ScalaFutures with OptionValues {

  it should "grant access with valid user authentication" in handlesRequest("user", "pass", true)
  it should "not grant access with invalid user authentication" in handlesRequest("user", "wrong_pass", false)

  def handlesRequest(user: String, pass: String, ok: Boolean) = {
    val dataHandler = new ImplicitHandler[IO, MockUser]{
      override def validateClient(maybeClientCredential: ClientCredential, request: ValidatedRequest): IO[Boolean] = IO.pure(true)

      //        override def findUser(
      //            maybeClientCredential: Option[ClientCredential],
      //            request: ValidatedRequest
      //        ): IO[Option[MockUser]] = {
      ////          val result = for {
      ////            user     <- request.params.get("username") if user.head == "user"
      ////            password <- request.params.get("password") if password.head == "pass"
      ////          } yield MockUser(10000, "username")
      //          //TODO: figure out what exactly findUser need
      //          if(ok) IO.pure(Some(MockUser(10000, "username"))) else IO.pure(None)
      //        }

      override def createAccessToken(authInfo: AuthInfo[MockUser]): IO[AccessToken] =
        IO.pure(AccessToken("token1", Some("refresh_token"), Some("all"), Some(3600 seconds), Instant.now()))

      override def findUser(maybeCredential: Option[ClientCredential], request: ValidatedImplicit): IO[Option[MockUser]] = if(ok) IO.pure(Some(MockUser(10000, "username"))) else IO.pure(None)

      /**
        * Returns stored access token by authorized information.
        *
        * If want to create new access token then have to return None
        *
        * @param authInfo This value is already authorized by system.
        * @return Access token returns to client.
        */
      override def getStoredAccessToken(authInfo: AuthInfo[MockUser]): IO[Option[AccessToken]] = IO.pure(None)

    }
    val handler = new ImplicitGrantHandler[IO, MockUser](dataHandler)

    val f = handler.handleRequest(
      ValidatedImplicit(ClientCredential("clientId1", Some("ClientSecret1")), Some("all"))
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
