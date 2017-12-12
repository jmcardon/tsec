package http4sExamples

import java.util.UUID

import cats.effect.IO
import org.http4s.HttpService
import org.http4s.dsl.io._
import tsec.authentication._
import tsec.mac.imports.{HMACSHA256, MacSigningKey}
import scala.concurrent.duration._

object SignedCookieExample {

  import ExampleAuthHelpers._

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

  val key: MacSigningKey[HMACSHA256] = HMACSHA256.generateKeyUnsafe() //Our Signing key. Instantiate in a safe way using GenerateLift

  val cookieAuth =
    SignedCookieAuthenticator(
      settings,
      cookieBackingStore,
      userStore,
      key
    )

  val Auth =
    SecuredRequestHandler(cookieAuth)

  /*
  Now from here, if want want to create services, we simply use the following
  (Note: Since the type of the service is HttpService[IO], we can mount it like any other endpoint!):
   */
  val service: HttpService[IO] = Auth {
    //Where user is the case class User above
    case request@GET -> Root / "api" asAuthed user =>
      /*
      Note: The request is of type: SecuredRequest, which carries:
      1. The request
      2. The Authenticator (i.e token)
      3. The identity (i.e in this case, User)
       */
      val r: SecuredRequest[IO, User, AuthenticatedCookie[HMACSHA256, Int]] = request
      Ok()
  }

}
