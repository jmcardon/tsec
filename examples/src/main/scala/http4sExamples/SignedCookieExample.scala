package http4sExamples

import java.util.UUID

import cats.Id
import cats.effect.IO
import cats.syntax.semigroupk._
import org.http4s.HttpService
import org.http4s.dsl.io._
import tsec.authentication._
import tsec.mac.jca.{HMACSHA256, MacSigningKey}

import scala.concurrent.duration._

object SignedCookieExample {

  import ExampleAuthHelpers._

  type AuthService = TSecAuthService[User, AuthenticatedCookie[HMACSHA256, Int], IO]

  val cookieBackingStore: BackingStore[IO, UUID, AuthenticatedCookie[HMACSHA256, Int]] =
    dummyBackingStore[IO, UUID, AuthenticatedCookie[HMACSHA256, Int]](_.id)

  // We create a way to store our users. You can attach this to say, your doobie accessor
  val userStore: BackingStore[IO, Int, User] = dummyBackingStore[IO, Int, User](_.id)

  val settings: TSecCookieSettings = TSecCookieSettings(
    cookieName = "tsec-auth",
    secure = false,
    expiryDuration = 10.minutes, // Absolute expiration time
    maxIdle = None // Rolling window expiration. Set this to a FiniteDuration if you intend to have one
  )

  //Our Signing key. Instantiate in a safe way using generateKey[F] where F[_]: Sync
  val key: MacSigningKey[HMACSHA256] = HMACSHA256.generateKey[Id]

  val cookieAuth =
    SignedCookieAuthenticator(
      settings,
      cookieBackingStore,
      userStore,
      key
    )

  val Auth =
    SecuredRequestHandler(cookieAuth)

  val service1: AuthService = TSecAuthService {
    //Where user is the case class User above
    case request @ GET -> Root / "api" asAuthed user =>
      /*
      Note: The request is of type: SecuredRequest, which carries:
      1. The request
      2. The Authenticator (i.e token)
      3. The identity (i.e in this case, User)
       */
      val r: SecuredRequest[IO, User, AuthenticatedCookie[HMACSHA256, Int]] = request
      Ok()
  }

  val service2: AuthService = TSecAuthService {
    case request @ GET -> Root / "api2" asAuthed user =>
      val r: SecuredRequest[IO, User, AuthenticatedCookie[HMACSHA256, Int]] = request
      Ok()
  }

  val liftedService1: HttpService[IO] = Auth.liftService(service1)
  val liftedComposed: HttpService[IO] = Auth.liftService(service1 <+> service2)

}
