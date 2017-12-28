package tsec.authentication

import java.time.Instant

import cats.data.OptionT
import cats.effect.IO
import org.http4s.headers.Authorization
import org.http4s.{AuthScheme, Credentials, Request}
import tsec.common.SecureRandomId

import scala.concurrent.duration._

class BearerTokenAuthenticatorTests extends RequestAuthenticatorSpec {

  def authspecTester = {
    val tokenStore: BackingStore[IO, SecureRandomId, TSecBearerToken[Int]] =
      dummyBackingStore[IO, SecureRandomId, TSecBearerToken[Int]](s => SecureRandomId.coerce(s.id))
    val dummyStore    = dummyBackingStore[IO, Int, DummyUser](_.id)
    val settings      = TSecTokenSettings(10.minutes, Some(10.minutes))
    val authenticator = BearerTokenAuthenticator(tokenStore, dummyStore, settings)
    new AuthSpecTester[TSecBearerToken[Int]](authenticator, dummyStore) {
      def embedInRequest(request: Request[IO], authenticator: TSecBearerToken[Int]): Request[IO] =
        request.putHeaders(Authorization(Credentials.Token(AuthScheme.Bearer, authenticator.id)))

      def expireAuthenticator(b: TSecBearerToken[Int]): IO[TSecBearerToken[Int]] =
        authenticator.update(b.copy(expiry = Instant.now.minusSeconds(30)))

      def timeoutAuthenticator(b: TSecBearerToken[Int]): IO[TSecBearerToken[Int]] =
        authenticator.update(b.copy(lastTouched = Some(Instant.now.minusSeconds(300000))))

      def wrongKeyAuthenticator: IO[TSecBearerToken[Int]] =
        IO.pure(TSecBearerToken(SecureRandomId.generate, -20, Instant.now(), None))
    }
  }

  AuthenticatorTest("Bearer token authenticator", authspecTester)
  requestAuthTests[TSecBearerToken[Int]]("Bearer token Request handler", authspecTester)

}
