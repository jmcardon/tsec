package tsec.authentication

import java.util.UUID

import cats.Id
import cats.data.OptionT
import cats.effect.IO
import org.http4s._
import org.http4s.dsl.io._
import org.http4s.headers.{Authorization => H4SA}
import tsec.common.SecureRandomId
import tsec.jws.mac.JWTMac
import tsec.mac.imports.HMACSHA256

import scala.concurrent.duration._

class AuthCompositionSpec extends AuthenticatorSpec {

  val backingStore1: BackingStore[IO, SecureRandomId, AugmentedJWT[HMACSHA256, Int]] =
    dummyBackingStore[IO, SecureRandomId, AugmentedJWT[HMACSHA256, Int]](s => SecureRandomId.coerce(s.id))

  val backingStore2: BackingStore[IO, SecureRandomId, TSecBearerToken[Int]] =
    dummyBackingStore[IO, SecureRandomId, TSecBearerToken[Int]](s => SecureRandomId.coerce(s.id))

  val backingStore3: BackingStore[IO, UUID, AuthenticatedCookie[HMACSHA256, Int]] =
    dummyBackingStore[IO, UUID, AuthenticatedCookie[HMACSHA256, Int]](_.id)

  val dummyStore = dummyBackingStore[IO, Int, DummyUser](_.id)

  val jwtSettings = TSecJWTSettings(
    expiryDuration = 10.minutes,
    maxIdle = None
  )

  val jwtAuthenticator = JWTAuthenticator.withBackingStoreArbitrary[IO, Int, DummyUser, HMACSHA256](
    jwtSettings,
    backingStore1,
    dummyStore,
    HMACSHA256.generateKey[Id]
  )

  val bearerTokenAuthenticator =
    BearerTokenAuthenticator(backingStore2, dummyStore, TSecTokenSettings(10.minutes, None))

  val cookieAuthenticator = SignedCookieAuthenticator(
    TSecCookieSettings(secure = false, expiryDuration = 10.minutes, maxIdle = None),
    backingStore3,
    dummyStore,
    HMACSHA256.generateKey[Id]
  )

  val service: TSecAuthService[DummyUser, Authenticator[Int], IO] = TSecAuthService {
    case GET -> Root asAuthed _ =>
      Ok()
  }

  val folded = jwtAuthenticator.foldAuthenticate(bearerTokenAuthenticator, cookieAuthenticator)(service)

  behavior of "Composability of Authenticators"

  it should "work for the first authenticator" in {

    val g = for {
      _       <- OptionT.liftF(dummyStore.put(DummyUser(1)))
      created <- OptionT.liftF(jwtAuthenticator.create(1))
      r <- folded.run(
        Request[IO]().putHeaders(Header(jwtSettings.headerName, JWTMac.toEncodedString[IO, HMACSHA256](created.jwt)))
      )
    } yield r

    g.getOrElse(Response.notFound).unsafeRunSync().status mustBe Status.Ok
  }

  it should "work for the second authenticator" in {

    val g = for {
      created <- OptionT.liftF(bearerTokenAuthenticator.create(1))
      r       <- folded.run(Request[IO]().putHeaders(H4SA(Credentials.Token(AuthScheme.Bearer, created.id))))
    } yield r

    g.getOrElse(Response.notFound).unsafeRunSync().status mustBe Status.Ok
  }

  it should "work for the third authenticator" in {

    val g = for {
      created <- OptionT.liftF(cookieAuthenticator.create(1))
      r       <- folded.run(Request[IO]().addCookie(created.toCookie))
    } yield r

    g.getOrElse(Response.notFound).unsafeRunSync().status mustBe Status.Ok
  }

  it should "fall through for an invalid request" in {

    val g = for {
      r <- folded.run(Request[IO]())
    } yield r

    g.getOrElse(Response.notFound).unsafeRunSync().status mustBe Status.Unauthorized
  }

}
