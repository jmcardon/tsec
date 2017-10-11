package tsec.authentication

import java.time.Instant
import java.util.UUID
import cats.data.OptionT
import cats.effect.IO
import org.http4s.{HttpDate, Request, Response}
import org.http4s.headers.`Set-Cookie`
import tsec.cipher.symmetric.imports._
import tsec.cookies.{AEADCookie, AEADCookieEncryptor}
import io.circe.parser.decode
import io.circe.generic.auto._
import scala.concurrent.duration._

class EncryptedCookieAuthenticatorSpec extends RequestAuthenticatorSpec[AuthEncryptedCookie[?, Int]] {

  private val cookieName = "hi"

  implicit def cookiebackingStore[A: AuthEncryptor] = dummyBackingStore[IO, UUID, AuthEncryptedCookie[A, Int]](_.id)

  def genStatefulAuthenticator[A](
      implicit authEncryptor: AuthEncryptor[A],
      keygen: CipherKeyGen[A],
      store: BackingStore[IO, UUID, AuthEncryptedCookie[A, Int]]
  ): AuthSpecTester[A, AuthEncryptedCookie[?, Int]] = {
    val authenticator = EncryptedCookieAuthenticator.withBackingStore[IO, A, Int, DummyUser](
      TSecCookieSettings(cookieName, false, expiryDuration = 10.minutes, maxIdle = Some(10.minutes)),
      store,
      dummyStore,
      keygen.generateKeyUnsafe()
    )
    new AuthSpecTester[A, AuthEncryptedCookie[?, Int]](authenticator) {

      def embedInRequest(request: Request[IO], authenticator: AuthEncryptedCookie[A, Int]): Request[IO] =
        request.addCookie(authenticator.toCookie)

      def extractFromResponse(response: Response[IO]): OptionT[IO, AuthEncryptedCookie[A, Int]] = {
        val cookieOpt = `Set-Cookie`.from(response.headers).map(_.cookie).find(_.name === cookieName)
        cookieOpt match {
          case None =>
            OptionT.none
          case Some(c) =>
            authenticator.extractAndValidate(Request[IO]().addCookie(c)).map(_.authenticator)
        }
      }

      def expireAuthenticator(b: AuthEncryptedCookie[A, Int]): OptionT[IO, AuthEncryptedCookie[A, Int]] = {
        val now     = Instant.now()
        val updated = b.copy[A, Int](expiry = HttpDate.unsafeFromInstant(now.minusSeconds(2000)))
        OptionT.liftF(store.update(updated)).map(_ => updated)
      }

      def timeoutAuthenticator(b: AuthEncryptedCookie[A, Int]): OptionT[IO, AuthEncryptedCookie[A, Int]] = {
        val now     = Instant.now()
        val updated = b.copy[A, Int](lastTouched = Some(HttpDate.unsafeFromInstant(now.minusSeconds(2000))))
        OptionT.liftF(store.update(updated)).map(_ => updated)
      }

      def wrongKeyAuthenticator: OptionT[IO, AuthEncryptedCookie[A, Int]] =
        EncryptedCookieAuthenticator
          .withBackingStore[IO, A, Int, DummyUser](
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
  ): AuthSpecTester[A, AuthEncryptedCookie[?, Int]] = {
    val secretKey = keygen.generateKeyUnsafe()
    val authenticator = EncryptedCookieAuthenticator.stateless[IO, A, Int, DummyUser](
      TSecCookieSettings(cookieName, false, expiryDuration = 10.minutes, maxIdle = Some(10.minutes)),
      dummyStore,
      secretKey
    )
    new AuthSpecTester[A, AuthEncryptedCookie[?, Int]](authenticator) {

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
            val coerced = AEADCookie.fromRaw[A](rawCookie.content)
            for {
              contentRaw <- OptionT.fromOption[IO](
                AEADCookieEncryptor.retrieveFromSigned[A](coerced, secretKey).toOption
              )
              internal <- OptionT.fromOption[IO](decode[AuthEncryptedCookie.Internal[Int]](contentRaw).toOption)
            } yield AuthEncryptedCookie.build[A, Int](internal, coerced, rawCookie)
        }
      }

      def expireAuthenticator(b: AuthEncryptedCookie[A, Int]): OptionT[IO, AuthEncryptedCookie[A, Int]] = {
        val now     = Instant.now()
        val updated = b.copy[A, Int](expiry = HttpDate.unsafeFromInstant(now.minusSeconds(2000)))
        authie.update(updated)
      }

      def timeoutAuthenticator(b: AuthEncryptedCookie[A, Int]): OptionT[IO, AuthEncryptedCookie[A, Int]] = {
        val now     = Instant.now()
        val updated = b.copy[A, Int](lastTouched = Some(HttpDate.unsafeFromInstant(now.minusSeconds(2000))))
        authie.update(updated)
      }

      def wrongKeyAuthenticator: OptionT[IO, AuthEncryptedCookie[A, Int]] =
        EncryptedCookieAuthenticator
          .stateless[IO, A, Int, DummyUser](
            TSecCookieSettings(cookieName, false, expiryDuration = 10.minutes, maxIdle = Some(10.minutes)),
            dummyStore,
            keygen.generateKeyUnsafe()
          )
          .create(123)
    }
  }

}
