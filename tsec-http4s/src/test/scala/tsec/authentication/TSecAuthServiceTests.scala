package tsec.authentication

import java.time.Instant

import cats.effect.IO
import cats.implicits._
import org.http4s._
import org.http4s.dsl.io._

class TSecAuthServiceTests extends AuthenticatorSpec {

  case class DummyAuthenticator(
      expiry: Instant = Instant.MIN,
      identity: Int = 0,
      lastTouched: Option[Instant] = None
  ) extends Authenticator[Int]

  behavior of "TSecAuthService"

  it should "compose and not fall through" in {

    val serviceOne: TSecAuthService[DummyUser, DummyAuthenticator, IO] =
      TSecAuthService {
        case POST -> Root asAuthed _ => Ok()
      }

    val serviceTwo: TSecAuthService[DummyUser, DummyAuthenticator, IO] =
      TSecAuthService {
        case GET -> Root asAuthed _ => Ok()
      }

    val service = serviceOne <+> serviceTwo

    val getReq  = Request[IO](method = Method.GET)
    val getSreq = SecuredRequest(getReq, DummyUser(0), DummyAuthenticator())

    val postReq  = Request[IO](method = Method.POST)
    val postSreq = SecuredRequest(postReq, DummyUser(0), DummyAuthenticator())

    service.orNotFound(getSreq).unsafeRunSync().status mustBe Status.Ok
    service.orNotFound(postSreq).unsafeRunSync().status mustBe Status.Ok
  }

}
