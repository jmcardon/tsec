package tsec.authentication

import java.time.Instant
import java.util.UUID

import cats.effect.IO
import org.http4s.Request
import tsec.mac.core.MacTag
import tsec.mac.imports._

import scala.concurrent.duration._

class SignedCookieAuthenticatorTests extends RequestAuthenticatorSpec {

  private val cookieName                     = "hi"
  implicit def cookieBackingStore[A: MacTag] = dummyBackingStore[IO, UUID, AuthenticatedCookie[A, Int]](_.id)

  def genAuthenticator[A: MacTag](
      implicit keyGenerator: MacKeyGenerator[A],
      store: BackingStore[IO, UUID, AuthenticatedCookie[A, Int]]
  ): AuthSpecTester[AuthenticatedCookie[A, Int]] = {
    val dummyStore = dummyBackingStore[IO, Int, DummyUser](_.id)
    val authenticator = SignedCookieAuthenticator[IO, Int, DummyUser, A](
      TSecCookieSettings(cookieName, false, expiryDuration = 10.minutes, maxIdle = Some(10.minutes)),
      store,
      dummyStore,
      keyGenerator.generateKeyUnsafe()
    )
    new AuthSpecTester[AuthenticatedCookie[A, Int]](authenticator, dummyStore) {

      def embedInRequest(request: Request[IO], authenticator: AuthenticatedCookie[A, Int]): Request[IO] =
        request.addCookie(authenticator.toCookie)

      def expireAuthenticator(b: AuthenticatedCookie[A, Int]): IO[AuthenticatedCookie[A, Int]] = {
        val now     = Instant.now()
        val updated = b.copy[A, Int](expiry = now.minusSeconds(2000))
        store.update(updated).map(_ => updated)
      }

      def timeoutAuthenticator(b: AuthenticatedCookie[A, Int]): IO[AuthenticatedCookie[A, Int]] = {
        val now     = Instant.now()
        val updated = b.copy[A, Int](lastTouched = Some(now.minusSeconds(2000)))
        store.update(updated).map(_ => updated)
      }

      def wrongKeyAuthenticator: IO[AuthenticatedCookie[A, Int]] =
        SignedCookieAuthenticator[IO, Int, DummyUser, A](
          TSecCookieSettings(cookieName, false, expiryDuration = 10.minutes, maxIdle = Some(10.minutes)),
          store,
          dummyStore,
          keyGenerator.generateKeyUnsafe()
        ).create(123)
    }
  }

  def CookieAuthTest[A: MacTag](string: String, auth: AuthSpecTester[AuthenticatedCookie[A, Int]]) =
    AuthenticatorTest[AuthenticatedCookie[A, Int]](string, auth)

  def CookieReqTest[A: MacTag](string: String, auth: AuthSpecTester[AuthenticatedCookie[A, Int]]) =
    requestAuthTests[AuthenticatedCookie[A, Int]](string, auth)

  CookieAuthTest[HMACSHA1]("HMACSHA1 Authenticator", genAuthenticator[HMACSHA1])
  CookieAuthTest[HMACSHA256]("HMACSHA256 Authenticator", genAuthenticator[HMACSHA256])
  CookieAuthTest[HMACSHA384]("HMACSHA384 Authenticator", genAuthenticator[HMACSHA384])
  CookieAuthTest[HMACSHA512]("HMACSHA512 Authenticator", genAuthenticator[HMACSHA512])

  CookieReqTest[HMACSHA1]("HMACSHA1 Authenticator", genAuthenticator[HMACSHA1])
  CookieReqTest[HMACSHA256]("HMACSHA256 Authenticator", genAuthenticator[HMACSHA256])
  CookieReqTest[HMACSHA384]("HMACSHA384 Authenticator", genAuthenticator[HMACSHA384])
  CookieReqTest[HMACSHA512]("HMACSHA512 Authenticator", genAuthenticator[HMACSHA512])

}
