package tsec.authentication

import java.time.Instant
import java.util.UUID

import cats.data.OptionT
import cats.effect.IO
import cats.syntax.either._
import io.circe.generic.auto._
import io.circe.parser.decode
import org.http4s.headers.`Set-Cookie`
import org.http4s.{Request, RequestCookie, Response}
import tsec.cipher.symmetric.jca._
import tsec.cookies.{AEADCookie, AEADCookieEncryptor}
import tsec.keygen.symmetric.IdKeyGen

import scala.concurrent.duration._

class EncryptedCookieAuthenticatorSpec extends RequestAuthenticatorSpec {

  private val cookieName = "hi"

  implicit def cookieBackingStore[A: AESGCM] = dummyBackingStore[IO, UUID, AuthEncryptedCookie[A, Int]](_.id)

  def genStatefulAuthenticator[A](
      implicit cipherAPI: AESGCM[A],
      idKeyGen: IdKeyGen[A, SecretKey],
      store: BackingStore[IO, UUID, AuthEncryptedCookie[A, Int]]
  ): AuthSpecTester[AuthEncryptedCookie[A, Int]] = {
    implicit val instance = cipherAPI.genEncryptor[IO]
    implicit val stategy  = cipherAPI.defaultIvStrategy[IO]

    val dummyStore = dummyBackingStore[IO, Int, DummyUser](_.id)
    val authenticator = EncryptedCookieAuthenticator.withBackingStore[IO, Int, DummyUser, A](
      TSecCookieSettings(cookieName, false, expiryDuration = 10.minutes, maxIdle = Some(10.minutes)),
      store,
      dummyStore,
      cipherAPI.unsafeGenerateKey
    )
    new AuthSpecTester[AuthEncryptedCookie[A, Int]](authenticator, dummyStore) {

      def embedInRequest(request: Request[IO], authenticator: AuthEncryptedCookie[A, Int]): Request[IO] = {
        val cookie = authenticator.toCookie
        request.addCookie(RequestCookie(cookie.name, cookie.content))
      }

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
            cipherAPI.unsafeGenerateKey
          )
          .create(123)
    }
  }

  def genStatelessAuthenticator[A](
      implicit cipherAPI: AESGCM[A],
      idKeyGen: IdKeyGen[A, SecretKey]
  ): AuthSpecTester[AuthEncryptedCookie[A, Int]] = {
    implicit val instance = cipherAPI.genEncryptor[IO]
    implicit val stategy  = cipherAPI.defaultIvStrategy[IO]

    val dummyStore = dummyBackingStore[IO, Int, DummyUser](_.id)
    val secretKey  = cipherAPI.unsafeGenerateKey
    val authenticator = EncryptedCookieAuthenticator.stateless[IO, Int, DummyUser, A](
      TSecCookieSettings(cookieName, false, expiryDuration = 10.minutes, maxIdle = Some(10.minutes)),
      dummyStore,
      secretKey
    )
    new AuthSpecTester[AuthEncryptedCookie[A, Int]](authenticator, dummyStore) {

      def embedInRequest(request: Request[IO], authenticator: AuthEncryptedCookie[A, Int]): Request[IO] = {
        val cookie = authenticator.toCookie
        request.addCookie(RequestCookie(cookie.name, cookie.content))
      }

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
              contentRaw <- OptionT.liftF(
                AEADCookieEncryptor.retrieveFromSigned[IO, A](coerced, secretKey)
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
            cipherAPI.unsafeGenerateKey
          )
          .create(123)
    }
  }

}
