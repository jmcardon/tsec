package http4sExamples

import cats.Id
import cats.effect.IO
import cats.syntax.semigroupk._
import org.http4s.HttpService
import org.http4s.dsl.io._
import tsec.authentication._
import tsec.common.SecureRandomId
import tsec.mac.jca.{HMACSHA256, MacSigningKey}

import scala.concurrent.duration._

object jwtStatefulExample {

  import ExampleAuthHelpers._

  type AuthService = TSecAuthService[User, AugmentedJWT[HMACSHA256, Int], IO]

  val jwtStore =
    dummyBackingStore[IO, SecureRandomId, AugmentedJWT[HMACSHA256, Int]](s => SecureRandomId.coerce(s.id))

  //We create a way to store our users. You can attach this to say, your doobie accessor
  val userStore: BackingStore[IO, Int, User] = dummyBackingStore[IO, Int, User](_.id)

  val signingKey
    : MacSigningKey[HMACSHA256] = HMACSHA256.generateKey[Id] //Our signing key. Instantiate in a safe way using GenerateLift

  val jwtStatefulAuth =
    JWTAuthenticator.backed.inBearerToken(
      expiryDuration = 10.minutes, //Absolute expiration time
      maxIdle = None,
      tokenStore = jwtStore,
      identityStore = userStore,
      signingKey = signingKey
    )

  val Auth =
    SecuredRequestHandler(jwtStatefulAuth)

  /*
  Now from here, if want want to create services, we simply use the following
  (Note: Since the type of the service is HttpService[IO], we can mount it like any other endpoint!):
   */
  val service1: AuthService = TSecAuthService {
    //Where user is the case class User above
    case request @ GET -> Root / "api" asAuthed user =>
      /*
      Note: The request is of type: SecuredRequest, which carries:
      1. The request
      2. The Authenticator (i.e token)
      3. The identity (i.e in this case, User)
       */
      val r: SecuredRequest[IO, User, AugmentedJWT[HMACSHA256, Int]] = request
      Ok()
  }

  val service2: AuthService = TSecAuthService {
    case request @ GET -> Root / "api2" asAuthed user =>
      val r: SecuredRequest[IO, User, AugmentedJWT[HMACSHA256, Int]] = request
      Ok()
  }

  val liftedService1: HttpService[IO] = Auth.liftService(service1)
  val liftedComposed: HttpService[IO] = Auth.liftService(service1 <+> service2)

}
