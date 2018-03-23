package http4sExamples

import cats.effect.IO
import cats.Id
import cats.implicits._
import org.http4s.dsl.io._
import tsec.authentication._
import tsec.common.SecureRandomId
import tsec.mac.jca.{HMACSHA256, MacSigningKey}

import scala.concurrent.duration._

package object jwtStatefulWithRolesExample {

  import ExampleAuthHelpers._

  val jwtStore =
    dummyBackingStore[IO, SecureRandomId, AugmentedJWT[HMACSHA256, Int]](s => SecureRandomId.coerce(s.id))

  //We create a way to store our users. You can attach this to say, your doobie accessor
  val userStore: BackingStore[IO, Int, User] = dummyBackingStore[IO, Int, User](_.id)

  val signingKey
  : MacSigningKey[HMACSHA256] = HMACSHA256.generateKey[Id] //Our signing key. Instantiate in a safe way using GenerateLift

  val jwtStatefulAuth =
    JWTAuthenticator.withBackingStore(
      expiryDuration = 10.minutes, //Absolute expiration time
      maxIdle = None,
      tokenStore = jwtStore,
      identityStore = userStore,
      signingKey = signingKey
    )

  val Auth =
    SecuredRequestHandler(jwtStatefulAuth)

  // could be reached only by the admin role
  private val adminRequiredService: TSecAuthService[User, AugmentedJWT[HMACSHA256, Int], IO] =
    TSecAuthService.withAuthorization(AdminRequired) {
      case request@GET -> Root / "api" / "admin-area" asAuthed user =>
        val r: SecuredRequest[IO, User, AugmentedJWT[HMACSHA256, Int]] = request
        Ok()
    }

  // could be reached by the admin and the customer roles
  private val customerRequiredService: TSecAuthService[User, AugmentedJWT[HMACSHA256, Int], IO] =
    TSecAuthService.withAuthorization(CustomerRequired) {
      case request@GET -> Root / "api" / "customer-area" asAuthed user =>
        val r: SecuredRequest[IO, User, AugmentedJWT[HMACSHA256, Int]] = request
        Ok()
    }

  /**
    * Multiple TSecAuthService can be combined with the combineK method (or its alias <+>)
    * by importing cats.implicits._ and org.http4s.implicits._.
    * Please ensure partial unification is enabled in your build.sbt.
    * scalacOptions ++= Seq("-Ypartial-unification")
    *
    * Be aware that to protect from spidering, tsec makes authenticated services consume all
    * (i.e it will never hit the rightmost service). That is why you can not lift to the HttpService[F] and compose.
    *
    */
  val service = Auth.liftService(adminRequiredService <+> customerRequiredService)
}
