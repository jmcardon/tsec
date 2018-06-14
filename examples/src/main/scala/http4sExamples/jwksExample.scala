package http4sExamples

import cats.effect.IO
import cats.syntax.semigroupk._
import org.http4s.dsl.io._
import org.http4s.{HttpService, Uri}
import tsec.authentication._
import tsec.signature.jca.SHA256withRSA

import scala.concurrent.duration._

object jwksExample {

  import ExampleAuthHelpers._

  case class User(id: String, name: String)

  type AuthService = TSecAuthService[User, AugmentedJWKS[SHA256withRSA, String], IO]

  //We create a way to store our users. You can attach this to say, your doobie accessor
  val userStore: BackingStore[IO, String, User] = dummyBackingStore[IO, String, User](_.id.toString)

  val jwksAuth =
    new JWKSAuthenticator[IO, String, User, SHA256withRSA](
      expiryDuration = 10.minutes,
      maxIdleDuration = None,
      identityStore = userStore,
      jwksUri = Uri.unsafeFromString("https://dev24.eu.auth0.com/.well-known/jwks.json"),
      minFetchDelay = 10.minutes)

  val Auth =
    SecuredRequestHandler(jwksAuth)

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
      val r: SecuredRequest[IO, User, AugmentedJWKS[SHA256withRSA, String]] = request
      Ok()
  }

  val service2: AuthService = TSecAuthService {
    case request @ GET -> Root / "api2" asAuthed user =>
      val r: SecuredRequest[IO, User, AugmentedJWKS[SHA256withRSA, String]] = request
      Ok()
  }

  val liftedService1: HttpService[IO] = Auth.liftService(service1)
  val liftedComposed: HttpService[IO] = Auth.liftService(service1 <+> service2)

}
