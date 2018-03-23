package http4sExamples

import java.util.UUID

import cats.effect.IO
import cats.syntax.semigroupk._
import org.http4s.HttpService
import org.http4s.dsl.io._
import tsec.authentication._
import tsec.cipher.symmetric.jca._

import scala.concurrent.duration._

object EncryptedCookieExample {

  import ExampleAuthHelpers._
  type AuthService = TSecAuthService[User, AuthEncryptedCookie[AES128GCM, Int], IO]

  implicit val encryptor   = AES128GCM.genEncryptor[IO].unsafeRunSync()
  implicit val gcmstrategy = AES128GCM.defaultIvStrategy[IO]

  val cookieBackingStore: BackingStore[IO, UUID, AuthEncryptedCookie[AES128GCM, Int]] =
    dummyBackingStore[IO, UUID, AuthEncryptedCookie[AES128GCM, Int]](_.id)

  // We create a way to store our users. You can attach this to say, your doobie accessor
  val userStore: BackingStore[IO, Int, User] = dummyBackingStore[IO, Int, User](_.id)

  val settings: TSecCookieSettings = TSecCookieSettings(
    cookieName = "tsec-auth",
    secure = false,
    expiryDuration = 10.minutes, // Absolute expiration time
    maxIdle = None // Rolling window expiration. Set this to a FiniteDuration if you intend to have one
  )

  val key: SecretKey[AES128GCM] = AES128GCM.unsafeGenerateKey //Our encryption key

  val authWithBackingStore = //Instantiate a stateful authenticator
    EncryptedCookieAuthenticator.withBackingStore(
      settings,
      cookieBackingStore,
      userStore,
      key
    )

  val stateless = //Instantiate a stateless authenticator
    EncryptedCookieAuthenticator.stateless(
      settings,
      userStore,
      key
    )

  val Auth =
    SecuredRequestHandler(stateless)

  /*
  Now from here, if want want to create services, we simply use the following
  (Note: Since the type of the service is HttpService[IO], we can mount it like any other endpoint!):
   */
  val rawService1: AuthService = TSecAuthService {
    //Where user is the case class User above
    case request @ GET -> Root / "api" asAuthed user =>
      /*
      Note: The request is of type: SecuredRequest, which carries:
      1. The request
      2. The Authenticator (i.e token)
      3. The identity (i.e in this case, User)
       */
      val r: SecuredRequest[IO, User, AuthEncryptedCookie[AES128GCM, Int]] = request
      Ok()
  }

  val rawService2: AuthService = TSecAuthService {
    case request @ GET -> Root / "api2" asAuthed user =>
      val r: SecuredRequest[IO, User, AuthEncryptedCookie[AES128GCM, Int]] = request
      Ok()
  }

  val liftedService: HttpService[IO]  = Auth.liftService(rawService1)
  val liftedComposed: HttpService[IO] = Auth.liftService(rawService1 <+> rawService2)

}
