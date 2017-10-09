package tsec.authentication

import java.util.UUID

import cats.effect.IO
import tsec.mac.imports._
import io.circe._
import org.http4s.Request
import tsec.common.ByteEV

import scala.concurrent.duration._

class CookieAuthenticatorTests extends AuthenticatorSpec {

  def genAuthenticator[A: MacTag: ByteEV](implicit keyGenerator: MacKeyGenerator[A]): CookieAuthenticator[IO, A, Int, DummyUser] =
    CookieAuthenticator[IO, A, Int, DummyUser](
      TSecCookieSettings("hi", false),
      dummyBackingStore[IO, UUID, AuthenticatedCookie[A, Int]](_.id),
      dummyStore,
      keyGenerator.generateKeyUnsafe(),
      10.minute,
      None
    )

  implicit def authenticatorEmbedder[A] = new Embedder[IO, AuthenticatedCookie[A, Int]] {
    def embedIntoRequest(e: AuthenticatedCookie[A, Int], req: Request[IO]): Request[IO] = req.addCookie(e.toCookie)
  }

  AuthenticatorTest[HMACSHA1]("HMACSHA1 Authenticator", genAuthenticator[HMACSHA1])

}
