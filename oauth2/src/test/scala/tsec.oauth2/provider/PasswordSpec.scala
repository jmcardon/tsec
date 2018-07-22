package tsec.oauth2.provider

import java.time.Instant

import cats.effect.IO
import cats.syntax.either._
import org.scalatest.Matchers._
import org.scalatest._
import tsec.oauth2.provider.ValidatedRequest.ValidatedPasswordNoClientCred
import tsec.oauth2.provider.ValidatedRequest.ValidatedPasswordWithClientCred
import tsec.oauth2.provider.grantHandler.PasswordNoClientCredGrantHandler
import tsec.oauth2.provider.grantHandler.PasswordNoClientCredHandler
import tsec.oauth2.provider.grantHandler.PasswordWithClientCredGrantHandler
import tsec.oauth2.provider.grantHandler.PasswordWithClientCredHandler

import scala.concurrent.duration._

class PasswordSpec extends FlatSpec with OptionValues {

  val passwordClientCredReq   = ValidatedPasswordWithClientCred(ClientCredential("clientId1", Some("clientSecret1")), "pass", "user", Some("all"))
  val passwordNoClientCredReq = ValidatedPasswordNoClientCred("pass", "user", Some("all"))

  "Password when client credential required" should "handle request" in handlesRequestPasswordWithClientCredReq(
    passwordClientCredReq
  )
  "Password when client credential not required" should "handle request" in handlesRequestPasswordNoClientCredReq(
    passwordNoClientCredReq
  )

  def handlesRequestPasswordWithClientCredReq(req: ValidatedPasswordWithClientCred) = {
    val dataHandler = new PasswordWithClientCredHandler[IO, MockUser] {
      override def validateClient(request: ValidatedPasswordWithClientCred): IO[Boolean] = IO.pure(true)

      override def findUser(
                             request: ValidatedPasswordWithClientCred
                           ): IO[Option[MockUser]] = IO.pure(Some(MockUser(10000, "username")))

      override def createAccessToken(authInfo: AuthInfo[MockUser]): IO[AccessToken] =
        IO.pure(AccessToken("token1", Some("refreshToken1"), Some("all"), Some(3600 seconds), Instant.now()))

      override def getStoredAccessToken(authInfo: AuthInfo[MockUser]): IO[Option[AccessToken]] = IO.pure(None)
      override def refreshAccessToken(authInfo: AuthInfo[MockUser], refreshToken: String): IO[AccessToken] = IO.pure(AccessToken("", Some(""), Some(""), Some(0 seconds), Instant.now()))
    }
    val handler = new PasswordWithClientCredGrantHandler[IO, MockUser](dataHandler)
    val f = handler.handleRequest(
      req
    )

    val result = f.value.unsafeRunSync().toOption.get
    result.tokenType should be("Bearer")
    result.accessToken should be("token1")
    result.expiresIn.value.toMillis should (be <= 3600L and be > 3595L)
    result.refreshToken should be(Some("refreshToken1"))
    result.scope should be(Some("all"))
  }

  def handlesRequestPasswordNoClientCredReq(req: ValidatedPasswordNoClientCred) = {
    val dataHandler = new PasswordNoClientCredHandler[IO, MockUser] {
      override def createAccessToken(authInfo: AuthInfo[MockUser]): IO[AccessToken] =
        IO.pure(AccessToken("token1", Some("refreshToken1"), Some("all"), Some(3600 seconds), Instant.now()))
      override def findUser(maybeCredential: Option[ClientCredential], request: ValidatedPasswordNoClientCred): IO[Option[MockUser]] = IO.pure(Some(MockUser(10000, "username")))
      override def getStoredAccessToken(authInfo: AuthInfo[MockUser]): IO[Option[AccessToken]] = IO.pure(None)
      override def refreshAccessToken(authInfo: AuthInfo[MockUser], refreshToken: String): IO[AccessToken] = IO.pure(AccessToken("", Some(""), Some(""), Some(0 seconds), Instant.now()))
    }
    val handler = new PasswordNoClientCredGrantHandler[IO, MockUser](dataHandler)
    val f = handler.handleRequest(
      req
    )
    val result = f.value.unsafeRunSync().toOption.get
    result.tokenType should be("Bearer")
    result.accessToken should be("token1")
    result.expiresIn.value.toMillis should (be <= 3600L and be > 3595L)
    result.refreshToken should be(Some("refreshToken1"))
    result.scope should be(Some("all"))
  }
}
