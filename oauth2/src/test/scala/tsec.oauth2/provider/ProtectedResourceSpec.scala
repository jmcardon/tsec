package tsec.oauth2.provider

import java.time.Instant

import cats.effect.IO
import org.scalatest._
import org.scalatest.Matchers._

import scala.concurrent.duration._

class ProtectedResourceSpec extends FlatSpec {
  val pureProtectedResourceHandler = new ProtectedResourceHandler[IO, MockUser] {

    override def findAccessToken(token: String): IO[Option[AccessToken]] =
      IO.pure(Some(AccessToken("token1", Some("refreshToken1"), Some("all"), Some(3600 seconds), Instant.now())))

    override def findAuthInfoByAccessToken(accessToken: AccessToken): IO[Option[AuthInfo[MockUser]]] =
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

  }

  val handler = ProtectedResource.apply[IO, MockUser](pureProtectedResourceHandler)

  it should "be handled request with token into header" in {
    val request = new ProtectedResourceRequest(
      Map("Authorization" -> Seq("OAuth token1")),
      Map("username"      -> Seq("user"), "password" -> Seq("pass"), "scope" -> Seq("all"))
    )

    handler.authorize(request).map(_ should be('right))
  }

  it should "be handled request with token into body" in {
    val request = new ProtectedResourceRequest(
      Map(),
      Map("access_token" -> Seq("token1"), "username" -> Seq("user"), "password" -> Seq("pass"), "scope" -> Seq("all"))
    )

    handler.authorize(request).map(_ should be('right))
  }

  it should "be lost expired" in {
    val request = new ProtectedResourceRequest(
      Map("Authorization" -> Seq("OAuth token1")),
      Map("username"      -> Seq("user"), "password" -> Seq("pass"), "scope" -> Seq("all"))
    )

    val dataHandler = new ProtectedResourceHandler[IO, MockUser] {

      override def findAccessToken(token: String): IO[Option[AccessToken]] =
        IO.pure(
          Some(
            AccessToken(
              "token1",
              Some("refreshToken1"),
              Some("all"),
              Some(3600 seconds),
              Instant.ofEpochMilli(System.currentTimeMillis() - 4000 * 1000)
            )
          )
        )

      override def findAuthInfoByAccessToken(accessToken: AccessToken): IO[Option[AuthInfo[MockUser]]] =
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

    }

    val localHandler = ProtectedResource.apply[IO, MockUser](dataHandler)
    val f = localHandler.authorize(request).value.unsafeRunSync()

    f shouldBe Left(ExpiredToken)
  }

  it should "be invalid request without token" in {
    val request = new ProtectedResourceRequest(
      Map(),
      Map("username" -> Seq("user"), "password" -> Seq("pass"), "scope" -> Seq("all"))
    )

    val f           = handler.authorize(request).value.unsafeRunSync()

    f shouldBe Left(InvalidRequest("Access token is not found"))
  }

  it should "be invalid request when not find an access token" in {
    val request = new ProtectedResourceRequest(
      Map("Authorization" -> Seq("OAuth token1")),
      Map("username"      -> Seq("user"), "password" -> Seq("pass"), "scope" -> Seq("all"))
    )

    val dataHandler = new ProtectedResourceHandler[IO, MockUser] {

      override def findAccessToken(token: String): IO[Option[AccessToken]] = IO.pure(None)

      override def findAuthInfoByAccessToken(accessToken: AccessToken): IO[Option[AuthInfo[MockUser]]] = IO.pure(None)

    }
    val localHandler = ProtectedResource.apply[IO, MockUser](dataHandler)
    val f = localHandler.authorize(request).value.unsafeRunSync()
    f shouldBe Left(InvalidToken("The access token is not found"))
  }

  it should "be invalid request when not find AuthInfo by token" in {
    val request = new ProtectedResourceRequest(
      Map("Authorization" -> Seq("OAuth token1")),
      Map("username"      -> Seq("user"), "password" -> Seq("pass"), "scope" -> Seq("all"))
    )

    val dataHandler = new ProtectedResourceHandler[IO, MockUser] {

      override def findAccessToken(token: String): IO[Option[AccessToken]] =
        IO.pure(Some(AccessToken("token1", Some("refreshToken1"), Some("all"), Some(3600 seconds), Instant.now())))

      override def findAuthInfoByAccessToken(accessToken: AccessToken): IO[Option[AuthInfo[MockUser]]] = IO.pure(None)

    }
    val localHandler = ProtectedResource.apply[IO, MockUser](dataHandler)
    val f = localHandler.authorize(request).value.unsafeRunSync()
    f shouldBe Left(InvalidToken("The access token is invalid"))
  }
}
