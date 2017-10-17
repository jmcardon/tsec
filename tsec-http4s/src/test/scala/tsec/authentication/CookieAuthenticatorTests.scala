package tsec.authentication

import java.time.Instant
import java.util.UUID

import cats.data.OptionT
import cats.effect.IO
import tsec.mac.imports._

import org.http4s.{HttpDate, Request}
import tsec.common.ByteEV

import scala.concurrent.duration._

class CookieAuthenticatorTests extends RequestAuthenticatorSpec[AuthenticatedCookie[?, Int]] {

  private val cookieName                     = "hi"
  implicit def cookiebackingStore[A: MacTag] = dummyBackingStore[IO, UUID, AuthenticatedCookie[A, Int]](_.id)

  def genAuthenticator[A: MacTag: ByteEV](
      implicit keyGenerator: MacKeyGenerator[A],
      store: BackingStore[IO, UUID, AuthenticatedCookie[A, Int]]
  ): AuthSpecTester[A, AuthenticatedCookie[?, Int]] = {
    val dummyStore = dummyBackingStore[IO, Int, DummyUser](_.id)
    val authenticator = CookieAuthenticator[IO, A, Int, DummyUser](
      TSecCookieSettings(cookieName, false, expiryDuration = 10.minutes, maxIdle = Some(10.minutes)),
      store,
      dummyStore,
      keyGenerator.generateKeyUnsafe(),
    )
    new AuthSpecTester[A, AuthenticatedCookie[?, Int]](authenticator, dummyStore) {

      def embedInRequest(request: Request[IO], authenticator: AuthenticatedCookie[A, Int]): Request[IO] =
        request.addCookie(authenticator.toCookie)


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
          TSecCookieSettings(cookieName, false, expiryDuration = 10.minutes, maxIdle = Some(10.minutes)),
          store,
          dummyStore,
          keyGenerator.generateKeyUnsafe()
        ).create(123)
    }
  }

  AuthenticatorTest[HMACSHA1]("HMACSHA1 Authenticator", genAuthenticator[HMACSHA1])
  AuthenticatorTest[HMACSHA256]("HMACSHA256 Authenticator", genAuthenticator[HMACSHA256])
  AuthenticatorTest[HMACSHA384]("HMACSHA384 Authenticator", genAuthenticator[HMACSHA384])
  AuthenticatorTest[HMACSHA512]("HMACSHA512 Authenticator", genAuthenticator[HMACSHA512])

  RequestAuthTests[HMACSHA1]("HMACSHA1 Authenticator", genAuthenticator[HMACSHA1])
  RequestAuthTests[HMACSHA256]("HMACSHA256 Authenticator", genAuthenticator[HMACSHA256])
  RequestAuthTests[HMACSHA384]("HMACSHA384 Authenticator", genAuthenticator[HMACSHA384])
  RequestAuthTests[HMACSHA512]("HMACSHA512 Authenticator", genAuthenticator[HMACSHA512])

}
