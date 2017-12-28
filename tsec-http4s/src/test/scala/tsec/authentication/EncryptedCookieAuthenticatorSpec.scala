package tsec.authentication

import java.time.Instant
import java.util.UUID
import cats.data.OptionT
import cats.effect.IO
import io.circe.java8.time.decodeInstant
import org.http4s.{Request, Response}
import org.http4s.headers.`Set-Cookie`
import tsec.cipher.symmetric.imports._
import tsec.cookies.{AEADCookie, AEADCookieEncryptor}
import io.circe.parser.decode
import io.circe.generic.auto._
import scala.concurrent.duration._

class EncryptedCookieAuthenticatorSpec extends RequestAuthenticatorSpec {

  private val cookieName = "hi"

  implicit def cookieBackingStore[A: AuthEncryptor] = dummyBackingStore[IO, UUID, AuthEncryptedCookie[A, Int]](_.id)

  def genStatefulAuthenticator[A](
      implicit authEncryptor: AuthEncryptor[A],
      keygen: CipherKeyGen[A],
      store: BackingStore[IO, UUID, AuthEncryptedCookie[A, Int]]
  ): AuthSpecTester[AuthEncryptedCookie[A, Int]] = {
    val dummyStore = dummyBackingStore[IO, Int, DummyUser](_.id)
    val authenticator = EncryptedCookieAuthenticator.withBackingStore[IO, Int, DummyUser, A](
      TSecCookieSettings(cookieName, false, expiryDuration = 10.minutes, maxIdle = Some(10.minutes)),
      store,
      dummyStore,
      keygen.generateKeyUnsafe()
    )
    new AuthSpecTester[AuthEncryptedCookie[A, Int]](authenticator, dummyStore) {

      def embedInRequest(request: Request[IO], authenticator: AuthEncryptedCookie[A, Int]): Request[IO] =
        request.addCookie(authenticator.toCookie)

      def expireAuthenticator(b: AuthEncryptedCookie[A, Int]): IO[AuthEncryptedCookie[A, Int]] = {
        val now     = Instant.now()
        val updated = b.copy[A, Int](expiry = now.minusSeconds(2000))
        store.update(updated).map(_ => updated)
      }

      def timeoutAuthenticator(b: AuthEncryptedCookie[A, Int]): IO[AuthEncryptedCookie[A, Int]] = {
        val now     = Instant.now()
        val updated = b.copy[A, Int](lastTouched = Some(now.minusSeconds(2000)))
        store.update(updated).map(_ => updated)
      }

      def wrongKeyAuthenticator: IO[AuthEncryptedCookie[A, Int]] =
        EncryptedCookieAuthenticator
          .withBackingStore[IO, Int, DummyUser, A](
            TSecCookieSettings(cookieName, false, expiryDuration = 10.minutes, maxIdle = Some(10.minutes)),
            store,
            dummyStore,
            keygen.generateKeyUnsafe()
          )
          .create(123)
    }
  }

  def genStatelessAuthenticator[A](
      implicit authEncryptor: AuthEncryptor[A],
      keygen: CipherKeyGen[A]
  ): AuthSpecTester[AuthEncryptedCookie[A, Int]] = {
    val dummyStore = dummyBackingStore[IO, Int, DummyUser](_.id)
    val secretKey  = keygen.generateKeyUnsafe()
    val authenticator = EncryptedCookieAuthenticator.stateless[IO, Int, DummyUser, A](
      TSecCookieSettings(cookieName, false, expiryDuration = 10.minutes, maxIdle = Some(10.minutes)),
      dummyStore,
      secretKey
    )
    new AuthSpecTester[AuthEncryptedCookie[A, Int]](authenticator, dummyStore) {

      def embedInRequest(request: Request[IO], authenticator: AuthEncryptedCookie[A, Int]): Request[IO] =
        request.addCookie(authenticator.toCookie)

      /** our method here has to be unique, since we cannot afford to renew the token for a stateless token, as
        * it carries rolling window expiration information.
        *
        * @return
        */
      def extractFromResponse(response: Response[IO]): OptionT[IO, AuthEncryptedCookie[A, Int]] = {
        val cookieOpt = `Set-Cookie`.from(response.headers).map(_.cookie).find(_.name === cookieName)
        cookieOpt match {
          case None =>
            OptionT.none
          case Some(rawCookie) =>
            val coerced = AEADCookie[A](rawCookie.content)
            for {
              contentRaw <- OptionT.fromOption[IO](
                AEADCookieEncryptor.retrieveFromSigned[A](coerced, secretKey).toOption
              )
              internal <- OptionT.fromOption[IO](decode[AuthEncryptedCookie.Internal[Int]](contentRaw).toOption)
            } yield AuthEncryptedCookie.build[A, Int](internal, coerced, rawCookie)
        }
      }

      def expireAuthenticator(b: AuthEncryptedCookie[A, Int]): IO[AuthEncryptedCookie[A, Int]] = {
        val now     = Instant.now()
        val updated = b.copy[A, Int](expiry = now.minusSeconds(2000))
        auth.update(updated)
      }

      def timeoutAuthenticator(b: AuthEncryptedCookie[A, Int]): IO[AuthEncryptedCookie[A, Int]] = {
        val now     = Instant.now()
        val updated = b.copy[A, Int](lastTouched = Some(now.minusSeconds(2000)))
        auth.update(updated)
      }

      def wrongKeyAuthenticator: IO[AuthEncryptedCookie[A, Int]] =
        EncryptedCookieAuthenticator
          .stateless[IO, Int, DummyUser, A](
            TSecCookieSettings(cookieName, false, expiryDuration = 10.minutes, maxIdle = Some(10.minutes)),
            dummyStore,
            keygen.generateKeyUnsafe()
          )
          .create(123)
    }
  }

}
