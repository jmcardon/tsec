package http4sExamples

import cats.effect.IO
import cats.syntax.semigroupk._
import org.http4s.HttpService
import org.http4s.dsl.io._
import tsec.authentication._
import tsec.common.SecureRandomId

import scala.concurrent.duration._

object BearerTokenExample {

  import ExampleAuthHelpers._

  val bearerTokenStore =
    dummyBackingStore[IO, SecureRandomId, TSecBearerToken[Int]](s => SecureRandomId.coerce(s.id))

  type AuthService = TSecAuthService[User, TSecBearerToken[Int], IO]

  //We create a way to store our users. You can attach this to say, your doobie accessor
  val userStore: BackingStore[IO, Int, User] = dummyBackingStore[IO, Int, User](_.id)

  val settings: TSecTokenSettings = TSecTokenSettings(
    expiryDuration = 10.minutes, //Absolute expiration time
    maxIdle = None
  )

  val bearerTokenAuth =
    BearerTokenAuthenticator(
      bearerTokenStore,
      userStore,
      settings
    )

  val Auth =
    SecuredRequestHandler(bearerTokenAuth)

  val authService1: AuthService = TSecAuthService {
    //Where user is the case class User above
    case request @ GET -> Root / "api" asAuthed user =>
      /*
      Note: The request is of type: SecuredRequest, which carries:
      1. The request
      2. The Authenticator (i.e token)
      3. The identity (i.e in this case, User)
       */
      val r: SecuredRequest[IO, User, TSecBearerToken[Int]] = request
      Ok()
  }

  val authedService2: AuthService = TSecAuthService {
    case GET -> Root / "api2" asAuthed user =>
      Ok()
  }

  val lifted: HttpService[IO]         = Auth.liftService(authService1)
  val liftedComposed: HttpService[IO] = Auth.liftService(authService1 <+> authedService2)
}
