package tsec.authentication

import java.time.Instant
import java.util.UUID

import cats.data.OptionT
import cats.effect.IO
import tsec.mac.imports._
import io.circe._
import org.http4s.{HttpDate, Request, Response}
import org.http4s.headers.`Set-Cookie`
import tsec.common.ByteEV

import scala.concurrent.duration._

class CookieAuthenticatorTests extends AuthenticatorSpec[AuthenticatedCookie[?, Int]] {

  private val cookieName                     = "hi"
  implicit def cookiebackingStore[A: MacTag] = dummyBackingStore[IO, UUID, AuthenticatedCookie[A, Int]](_.id)

  def genAuthenticator[A: MacTag: ByteEV](
      implicit keyGenerator: MacKeyGenerator[A],
      store: BackingStore[IO, UUID, AuthenticatedCookie[A, Int]]
  ): AuthSpecTester[A, AuthenticatedCookie[?, Int]] = {
    val authenticator = CookieAuthenticator[IO, A, Int, DummyUser](
      TSecCookieSettings(cookieName, false),
      store,
      dummyStore,
      keyGenerator.generateKeyUnsafe(),
      10.minute,
      Some(20.minutes)
    )
    new AuthSpecTester[A, AuthenticatedCookie[?, Int]](authenticator) {

      def embedInRequest(request: Request[IO], authenticator: AuthenticatedCookie[A, Int]): Request[IO] =
        request.addCookie(authenticator.toCookie)

      def extractFromResponse(response: Response[IO]): OptionT[IO, AuthenticatedCookie[A, Int]] = {
        val cookieOpt = `Set-Cookie`.from(response.headers).map(_.cookie).find(_.name === cookieName)
        cookieOpt match {
          case None =>
            OptionT.none
          case Some(c) =>
            authenticator.extractAndValidate(Request[IO]().addCookie(c)).map(_.authenticator)
        }
      }

      def expireAuthenticator(b: AuthenticatedCookie[A, Int]): OptionT[IO, AuthenticatedCookie[A, Int]] = {
        val now     = Instant.now()
        val updated = b.copy[A, Int](expiry = HttpDate.unsafeFromInstant(now.minusSeconds(2000)))
        OptionT.liftF(store.update(updated)).map(_ => updated)
      }

      def timeoutAuthenticator(b: AuthenticatedCookie[A, Int]): OptionT[IO, AuthenticatedCookie[A, Int]] = {
        val now     = Instant.now()
        val updated = b.copy[A, Int](lastTouched = Some(HttpDate.unsafeFromInstant(now.minusSeconds(2000))))
        OptionT.liftF(store.update(updated)).map(_ => updated)
      }

      def wrongKeyAuthenticator: OptionT[IO, AuthenticatedCookie[A, Int]] =
        CookieAuthenticator[IO, A, Int, DummyUser](
          TSecCookieSettings(cookieName, false),
          store,
          dummyStore,
          keyGenerator.generateKeyUnsafe(),
          10.minute,
          Some(20.minutes)
        ).create(123)
    }
  }

  AuthenticatorTest[HMACSHA1]("HMACSHA1 Authenticator", genAuthenticator[HMACSHA1])
  AuthenticatorTest[HMACSHA256]("HMACSHA256 Authenticator", genAuthenticator[HMACSHA256])
  AuthenticatorTest[HMACSHA384]("HMACSHA384 Authenticator", genAuthenticator[HMACSHA384])
  AuthenticatorTest[HMACSHA512]("HMACSHA512 Authenticator", genAuthenticator[HMACSHA512])

}
