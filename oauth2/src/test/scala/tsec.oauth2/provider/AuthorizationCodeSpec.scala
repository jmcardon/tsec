package tsec.oauth2.provider

import java.time.Instant

import org.scalatest.Matchers._
import org.scalatest._

import scala.concurrent.duration._
import cats.effect.IO
import tsec.oauth2.provider.GrantHandler.AuthorizationCode

class AuthorizationCodeSpec extends FlatSpec with OptionValues {

  val handler = new AuthorizationCode[IO]

  it should "handle request" in {
    val request = new ValidatedRequest(
      Map(),
      Map(
        "client_id"     -> Seq("clientId1"),
        "client_secret" -> Seq("clientSecret1"),
        "code"          -> Seq("code1"),
        "redirect_uri"  -> Seq("http://example.com/")
      )
    )
    var codeDeleted: Boolean = false
    val f = handler.handleRequest(
      request,
      new MockDataHandler() {
        override def validateClient(maybeClientCredential: ClientCredential, request: ValidatedRequest): IO[Boolean] =
          IO.pure(true)
        override def findAuthInfoByCode(code: String): IO[Option[AuthInfo[MockUser]]] =
          IO.pure(
            Some(
              AuthInfo(
                user = MockUser(10000, "username"),
                clientId = Some("clientId1"),
                scope = Some("all"),
                redirectUri = Some("http://example.com/")
              )
            )
          )

        override def createAccessToken(authInfo: AuthInfo[MockUser]): IO[AccessToken] =
          IO.pure(AccessToken("token1", Some("refreshToken1"), Some("all"), Some(3600 seconds),Instant.now()))

        override def deleteAuthCode(code: String): IO[Unit] = {
          Thread.sleep(300)
          codeDeleted = true
          IO.pure(Unit)
        }
      }
    )

    val result = f.value.unsafeRunSync().toOption.get
    codeDeleted shouldBe true
    result.tokenType shouldBe "Bearer"
    result.accessToken shouldBe "token1"
    result.expiresIn.value.toMillis should (be <= 3600L and be > 3595L)
    result.refreshToken shouldBe Some("refreshToken1")
    result.scope shouldBe Some("all")
  }

  it should "handle request if redirectUrl is none" in {
    val request = new ValidatedRequest(
      Map(),
      Map(
        "client_id"     -> Seq("clientId1"),
        "client_secret" -> Seq("clientSecret1"),
        "code"          -> Seq("code1")
      )
    )
    val f = handler.handleRequest(
      request,
      new MockDataHandler() {
        override def validateClient(maybeClientCredential: ClientCredential, request: ValidatedRequest): IO[Boolean] =
          IO.pure(true)
        override def findAuthInfoByCode(code: String): IO[Option[AuthInfo[MockUser]]] =
          IO.pure(
            Some(
              AuthInfo(
                user = MockUser(10000, "username"),
                clientId = Some("clientId1"),
                scope = Some("all"),
                redirectUri = None
              )
            )
          )

        override def createAccessToken(authInfo: AuthInfo[MockUser]): IO[AccessToken] =
          IO.pure(AccessToken("token1", Some("refreshToken1"), Some("all"), Some(3600 seconds), Instant.now()))
      }
    )

    val result = f.value.unsafeRunSync().toOption.get
    result.tokenType shouldBe "Bearer"
    result.accessToken shouldBe "token1"
    result.expiresIn.value.toMillis should (be <= 3600L and be > 2595L)
    result.refreshToken shouldBe Some("refreshToken1")
    result.scope shouldBe Some("all")
  }

  it should "return a Failure IO" in {
    val request = new ValidatedRequest(
      Map(),
      Map(
        "client_id"     -> Seq("clientId1"),
        "client_secret" -> Seq("clientSecret1"),
        "code"          -> Seq("code1"),
        "redirect_uri"  -> Seq("http://example.com/")
      )
    )
    val f = handler.handleRequest(
      request,
      new MockDataHandler() {

        override def findAuthInfoByCode(code: String): IO[Option[AuthInfo[MockUser]]] =
          IO.pure(
            Some(
              AuthInfo(
                user = MockUser(10000, "username"),
                clientId = Some("clientId1"),
                scope = Some("all"),
                redirectUri = Some("http://example.com/")
              )
            )
          )

        override def createAccessToken(authInfo: AuthInfo[MockUser]): IO[AccessToken] =
          IO.pure(AccessToken("token1", Some("refreshToken1"), Some("all"), Some(3600 seconds), Instant.now()))

        override def deleteAuthCode(code: String): IO[Unit] =
          IO.raiseError(new Exception())
      }
    )

    val result = f.value.unsafeRunSync()
    result shouldBe(Left(InvalidClient("Invalid client or client is not authorized")))
  }
}
