package tsec.oauth2.provider

import java.time.Instant

import cats.effect.IO
import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.Matchers._
import tsec.oauth2.provider.ValidatedRequest.ValidatedPasswordWithClientCred
import tsec.oauth2.provider.grantHandler.PasswordNoClientCredHandler
import tsec.oauth2.provider.grantHandler.PasswordWithClientCredHandler

import scala.concurrent.duration._

class TokenEndPointSpec extends AnyFlatSpec {
  val dataHandler = new PasswordWithClientCredHandler[IO, MockUser]{

    override def validateClient(request: ValidatedPasswordWithClientCred): IO[Boolean] =
      IO.pure(true)

    override def findUser(
        request: ValidatedPasswordWithClientCred
    ): IO[Option[MockUser]] = IO.pure(Some(MockUser(10000, "username")))

    override def createAccessToken(authInfo: AuthInfo[MockUser]): IO[AccessToken] =
      IO.pure(AccessToken("token1", None, Some("all"), Some(3600 seconds), Instant.now()))
    override def getStoredAccessToken(authInfo: AuthInfo[MockUser]): IO[Option[AccessToken]] = IO.pure(None)
    override def refreshAccessToken(authInfo: AuthInfo[MockUser], refreshToken: String): IO[AccessToken] = IO.pure(AccessToken("", Some(""), Some(""), Some(0 seconds), Instant.now()))
  }
  val te = new TokenEndpoint[IO, MockUser](DataHandlers(Some(dataHandler), None, None, None, None, None))

  it should "be handled request" in {
    val headers                  = Map("Authorization" -> Seq("Basic Y2xpZW50X2lkX3ZhbHVlOmNsaWVudF9zZWNyZXRfdmFsdWU="))
    val params = Map("grant_type"    -> Seq("password"), "username" -> Seq("user"), "password" -> Seq("pass"), "scope" -> Seq("all"))
    val result = te.authorize(headers, params, true).value.unsafeRunSync()
    result should be('right)
  }

  it should "be error if grant type doesn't exist" in {
    val headers                  = Map("Authorization" -> Seq("Basic Y2xpZW50X2lkX3ZhbHVlOmNsaWVudF9zZWNyZXRfdmFsdWU="))
    val params = Map("username"      -> Seq("user"), "password" -> Seq("pass"), "scope" -> Seq("all"))
    val res = te.authorize(headers, params, true).value.unsafeRunSync()
    res shouldBe (Left(InvalidRequest("Missing grant type")))
  }

  it should "error if grant type is wrong" in {
    val headers                  = Map("Authorization" -> Seq("Basic Y2xpZW50X2lkX3ZhbHVlOmNsaWVudF9zZWNyZXRfdmFsdWU="))
    val params = Map("grant_type"    -> Seq("test"), "username" -> Seq("user"), "password" -> Seq("pass"), "scope" -> Seq("all"))
    val res = te.authorize(headers, params).value.unsafeRunSync()
    res shouldBe (Left(UnsupportedGrantType("unsupported grant type: test")))
  }

  it should "be invalid request without client credential" in {
    val params = Map("grant_type" -> Seq("password"), "username" -> Seq("user"), "password" -> Seq("pass"), "scope" -> Seq("all"))
    val res = te.authorize(Map(), params).value.unsafeRunSync()
    res shouldBe (Left(InvalidClient("Failed to parse client credential from header (Missing authorization header) and params")))
  }

  it should "not be invalid request without client credential when not required" in {
    val params                  = Map("grant_type" -> Seq("password"), "username" -> Seq("user"), "password" -> Seq("pass"), "scope" -> Seq("all"))
    val dataHandler = new PasswordNoClientCredHandler[IO, MockUser]{
      override def createAccessToken(authInfo: AuthInfo[MockUser]): IO[AccessToken] =
        IO.pure(AccessToken("token1", None, Some("all"), Some(3600 seconds), Instant.now()))
      override def getStoredAccessToken(authInfo: AuthInfo[MockUser]): IO[Option[AccessToken]] = IO.pure(None)
      override def refreshAccessToken(authInfo: AuthInfo[MockUser], refreshToken: String): IO[AccessToken] = IO.pure(AccessToken("", Some(""), Some(""), Some(0 seconds), Instant.now()))
      override def findUser(maybeCredential: Option[ClientCredential], request: ValidatedRequest.ValidatedPasswordNoClientCred): IO[Option[MockUser]] = IO.pure(Some(MockUser(10000, "username")))
    }
    val t = TokenEndpoint(DataHandlers(None, Some(dataHandler), None, None, None, None))
    val res = t.authorize(Map.empty, params, false).value.unsafeRunSync()
    res should be('right)
  }

  it should "be invalid grant if client information is wrong" in {
    val headers                  = Map("Authorization" -> Seq("Basic Y2xpZW50X2lkX3ZhbHVlOmNsaWVudF9zZWNyZXRfdmFsdWU="))
    val params = Map("grant_type"    -> Seq("password"), "username" -> Seq("user"), "password" -> Seq("pass"), "scope" -> Seq("all"))
    val dataHandler = new PasswordWithClientCredHandler[IO, MockUser]{
      override def validateClient(request: ValidatedPasswordWithClientCred): IO[Boolean] =
        IO.pure(false)

      override def findUser(
                             request: ValidatedPasswordWithClientCred
                           ): IO[Option[MockUser]] = ???

      override def createAccessToken(authInfo: AuthInfo[MockUser]): IO[AccessToken] = ???
      override def getStoredAccessToken(authInfo: AuthInfo[MockUser]): IO[Option[AccessToken]] = IO.pure(None)
      override def refreshAccessToken(authInfo: AuthInfo[MockUser], refreshToken: String): IO[AccessToken] = IO.pure(AccessToken("", Some(""), Some(""), Some(0 seconds), Instant.now()))
    }
    val te = TokenEndpoint(DataHandlers(Some(dataHandler), None, None, None, None, None))
    val f = te.authorize(headers, params).value.unsafeRunSync()
    f shouldBe Left(InvalidClient("Invalid client or client is not authorized"))
  }

  it should "be Failure when DataHandler throws Exception" in {
    val dataHandler = new PasswordWithClientCredHandler[IO, MockUser]{

      override def validateClient(request: ValidatedPasswordWithClientCred): IO[Boolean] =
        IO.pure(true)

      override def findUser(
                             request: ValidatedPasswordWithClientCred
                           ): IO[Option[MockUser]] = IO.pure(Some(MockUser(10000, "username")))

      override def createAccessToken(authInfo: AuthInfo[MockUser]): IO[AccessToken] = throw new Exception("Failure")
      override def getStoredAccessToken(authInfo: AuthInfo[MockUser]): IO[Option[AccessToken]] = IO.pure(None)
      override def refreshAccessToken(authInfo: AuthInfo[MockUser], refreshToken: String): IO[AccessToken] = IO.pure(AccessToken("", Some(""), Some(""), Some(0 seconds), Instant.now()))
    }
    val te = TokenEndpoint(DataHandlers(Some(dataHandler), None, None, None, None, None))
    val headers                  = Map("Authorization" -> Seq("Basic Y2xpZW50X2lkX3ZhbHVlOmNsaWVudF9zZWNyZXRfdmFsdWU="))
    val params = Map("grant_type"    -> Seq("password"), "username" -> Seq("user"), "password" -> Seq("pass"), "scope" -> Seq("all"))
    val f = te.authorize(headers, params).value.unsafeRunSync()

    f shouldBe(Left(FailedToIssueAccessToken("Failure")))
  }

  it should "be a 401 InvalidClient failure when the Authorization header is present and there is a problem extracting the client credentials" in {
    val headers                  = Map("Authorization" -> Seq("Digest Y2xpZW50X2lkX3ZhbHVlOmNsaWVudF9zZWNyZXRfdmFsdWU="))
    val params = Map("grant_type"    -> Seq("password"), "username" -> Seq("username"), "password" -> Seq("pass"), "scope" -> Seq("all"))
    val res = te.authorize(headers, params).value.unsafeRunSync()
    res shouldBe Left(InvalidAuthorizationHeader)
  }

  it should "be a 401 InvalidClient failure when the Authorization header is present but invalid - even when an invalid grant handler is provided" in {
    val headers                  = Map("Authorization" -> Seq("Digest Y2xpZW50X2lkX3ZhbHVlOmNsaWVudF9zZWNyZXRfdmFsdWU="))
    val params = Map(
      "grant_type" -> Seq("made_up_grant"),
      "username"   -> Seq("user"),
      "password"   -> Seq("pass"),
      "scope"      -> Seq("all")
    )

    val res = te.authorize(headers, params).value.unsafeRunSync()
    res shouldBe (Left(UnsupportedGrantType("unsupported grant type: made_up_grant")))
  }
}
