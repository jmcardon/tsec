package tsec.oauth2.provider

import java.time.Instant

import cats.effect.IO
import org.scalatest.FlatSpec
import org.scalatest.Matchers._

import scala.concurrent.duration._

class TokenEndPointSpec extends FlatSpec {
  val te                  = new TokenEndpoint[IO]

  def pureDataHandler() = new MockDataHandler() {

    override def validateClient(maybeClientCredential: ClientCredential, request: ValidatedRequest): IO[Boolean] =
      IO.pure(true)

    override def findUser(
        maybeClientCredential: Option[ClientCredential],
        request: ValidatedRequest
    ): IO[Option[MockUser]] = IO.pure(Some(MockUser(10000, "username")))

    override def createAccessToken(authInfo: AuthInfo[MockUser]): IO[AccessToken] =
      IO.pure(AccessToken("token1", None, Some("all"), Some(3600 seconds), Instant.now()))

  }

  it should "be handled request" in {
    val request = new ValidatedRequest(
      Map("Authorization" -> Seq("Basic Y2xpZW50X2lkX3ZhbHVlOmNsaWVudF9zZWNyZXRfdmFsdWU=")),
      Map("grant_type"    -> Seq("password"), "username" -> Seq("user"), "password" -> Seq("pass"), "scope" -> Seq("all"))
    )

    val dataHandler = pureDataHandler()
    val result      = te.handleRequest(request, dataHandler, true).value.unsafeRunSync()

    result should be('right)
  }

  it should "be error if grant type doesn't exist" in {
    val request = new ValidatedRequest(
      Map("Authorization" -> Seq("Basic Y2xpZW50X2lkX3ZhbHVlOmNsaWVudF9zZWNyZXRfdmFsdWU=")),
      Map("username"      -> Seq("user"), "password" -> Seq("pass"), "scope" -> Seq("all"))
    )

    val dataHandler = pureDataHandler()
    val f           = te.handleRequest(request, dataHandler, true).value.unsafeRunSync()

    f shouldBe (Left(InvalidRequest("Missing grant type")))
  }

  it should "error if grant type is wrong" in {
    val request = new ValidatedRequest(
      Map("Authorization" -> Seq("Basic Y2xpZW50X2lkX3ZhbHVlOmNsaWVudF9zZWNyZXRfdmFsdWU=")),
      Map("grant_type"    -> Seq("test"), "username" -> Seq("user"), "password" -> Seq("pass"), "scope" -> Seq("all"))
    )

    val dataHandler = pureDataHandler()
    val f           = te.handleRequest(request, dataHandler, true).value.unsafeRunSync()
    f shouldBe (Left(UnsupportedGrantType("unsupported grant type: test")))
  }

  it should "be invalid request without client credential" in {
    val request = new ValidatedRequest(
      Map(),
      Map("grant_type" -> Seq("password"), "username" -> Seq("user"), "password" -> Seq("pass"), "scope" -> Seq("all"))
    )

    val dataHandler = pureDataHandler()
    val f           = te.handleRequest(request, dataHandler, true).value.unsafeRunSync()
    f shouldBe (Left(InvalidClient("Failed to parse client credential from header (Missing authorization header) and params")))
  }

  it should "not be invalid request without client credential when not required" in {
    val request = new ValidatedRequest(
      Map(),
      Map("grant_type" -> Seq("password"), "username" -> Seq("user"), "password" -> Seq("pass"), "scope" -> Seq("all"))
    )

    val dataHandler = pureDataHandler()

    val f = te.handleRequest(request, dataHandler, false).value.unsafeRunSync()

    f should be('right)
  }

  it should "be invalid client if client information is wrong" in {
    val request = new ValidatedRequest(
      Map("Authorization" -> Seq("Basic Y2xpZW50X2lkX3ZhbHVlOmNsaWVudF9zZWNyZXRfdmFsdWU=")),
      Map("grant_type"    -> Seq("password"), "username" -> Seq("user"), "password" -> Seq("pass"), "scope" -> Seq("all"))
    )

    val dataHandler = new MockDataHandler() {
      override def validateClient(maybeClientCredential: ClientCredential, request: ValidatedRequest): IO[Boolean] =
        IO.pure(false)
    }

    val f = te.handleRequest(request, dataHandler, true).value.unsafeRunSync()
    f shouldBe Left(InvalidClient("Invalid client or client is not authorized"))
  }

  it should "be Failure when DataHandler throws Exception" in {
    val request = new ValidatedRequest(
      Map("Authorization" -> Seq("Basic Y2xpZW50X2lkX3ZhbHVlOmNsaWVudF9zZWNyZXRfdmFsdWU=")),
      Map("grant_type"    -> Seq("password"), "username" -> Seq("user"), "password" -> Seq("pass"), "scope" -> Seq("all"))
    )

    def dataHandler = new MockDataHandler() {

      override def validateClient(maybeClientCredential: ClientCredential, request: ValidatedRequest): IO[Boolean] =
        IO.pure(true)

      override def findUser(
          maybeClientCredential: Option[ClientCredential],
          request: ValidatedRequest
      ): IO[Option[MockUser]] = IO.pure(Some(MockUser(10000, "username")))

      override def createAccessToken(authInfo: AuthInfo[MockUser]): IO[AccessToken] = throw new Exception("Failure")

    }

    val f = te.handleRequest(request, dataHandler, true).value.unsafeRunSync()

    f shouldBe(Left(FailedToIssueAccessToken("Failure")))
  }

  it should "be a 401 InvalidClient failure when the Authorization header is present and there is a problem extracting the client credentials" in {
    val request = new ValidatedRequest(
      //Use Digest instead of Bearer.
      Map("Authorization" -> Seq("Digest Y2xpZW50X2lkX3ZhbHVlOmNsaWVudF9zZWNyZXRfdmFsdWU=")),
      Map("grant_type"    -> Seq("password"), "username" -> Seq("username"), "password" -> Seq("pass"), "scope" -> Seq("all"))
    )

    val dataHandler = new MockDataHandler() {

      override def validateClient(maybeClientCredential: ClientCredential, request: ValidatedRequest): IO[Boolean] =
        IO.pure(true)

    }

    val result = te.handleRequest(request, dataHandler, true).value.unsafeRunSync()

    result shouldBe Left(InvalidAuthorizationHeader)
  }

  it should "be a 401 InvalidClient failure when the Authorization header is present but invalid - even when an invalid grant handler is provided" in {
    val request = new ValidatedRequest(
      //Use Digest instead of Bearer.
      Map("Authorization" -> Seq("Digest Y2xpZW50X2lkX3ZhbHVlOmNsaWVudF9zZWNyZXRfdmFsdWU=")),
      Map(
        "grant_type" -> Seq("made_up_grant"),
        "username"   -> Seq("user"),
        "password"   -> Seq("pass"),
        "scope"      -> Seq("all")
      )
    )

    val dataHandler = new MockDataHandler() {

      override def validateClient(maybeClientCredential: ClientCredential, request: ValidatedRequest): IO[Boolean] =
        IO.pure(true)

    }

    val f = te.handleRequest(request, dataHandler, true).value.unsafeRunSync()
    f shouldBe (Left(UnsupportedGrantType("unsupported grant type: made_up_grant")))
  }
}
