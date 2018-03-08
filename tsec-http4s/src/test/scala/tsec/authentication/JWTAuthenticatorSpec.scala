package tsec.authentication

import java.time.Instant

import cats.effect.IO
import org.http4s.{Header, Request}
import tsec.cipher.symmetric.imports._
import tsec.common.SecureRandomId
import tsec.jws.mac.{JWSMacCV, JWTMac}
import tsec.jwt.algorithms.JWTMacAlgo
import tsec.keygen.symmetric.IdKeyGen
import tsec.mac.core._
import tsec.mac.imports._

import scala.concurrent.duration._

class JWTAuthenticatorSpec extends RequestAuthenticatorSpec {

  private val settings =
    TSecJWTSettings(
      "hi",
      10.minutes,
      Some(10.minutes)
    )

  implicit def backingStore[A]: BackingStore[IO, SecureRandomId, JWTMac[A]] =
    dummyBackingStore[IO, SecureRandomId, JWTMac[A]](s => SecureRandomId.coerce(s.id))

  implicit def backingStore2[A]: BackingStore[IO, SecureRandomId, AugmentedJWT[A, Int]] =
    dummyBackingStore[IO, SecureRandomId, AugmentedJWT[A, Int]](s => SecureRandomId.coerce(s.id))

  /** Stateful tests using Authorization: Header
    *
    */
  def stateful[A: JWTMacAlgo: JCAMacTag](
      implicit cv: JWSMacCV[IO, A],
      macKeyGen: IdKeyGen[A, MacSigningKey],
      store: BackingStore[IO, SecureRandomId, AugmentedJWT[A, Int]]
  ): AuthSpecTester[AugmentedJWT[A, Int]] = {
    val dummyStore = dummyBackingStore[IO, Int, DummyUser](_.id)
    val macKey     = macKeyGen.generateKey
    val authenticator = JWTAuthenticator.withBackingStore[IO, Int, DummyUser, A](
      settings.expiryDuration,
      settings.maxIdle,
      store,
      dummyStore,
      macKey
    )

    new AuthSpecTester[AugmentedJWT[A, Int]](authenticator, dummyStore) {

      def embedInRequest(request: Request[IO], authenticator: AugmentedJWT[A, Int]): Request[IO] =
        request.putHeaders(buildBearerAuthHeader(JWTMac.toEncodedString[IO, A](authenticator.jwt)))

      def expireAuthenticator(b: AugmentedJWT[A, Int]): IO[AugmentedJWT[A, Int]] =
        for {
          newToken <- JWTMac
            .build[IO, A](
              b.jwt.body.withExpiry(Instant.now().minusSeconds(10000)),
              macKey
            )

          expired <- store.update(b.copy(jwt = newToken, expiry = Instant.now().minusSeconds(10000)))
        } yield expired

      def timeoutAuthenticator(b: AugmentedJWT[A, Int]): IO[AugmentedJWT[A, Int]] = {
        val newInternal = b.copy(lastTouched = Some(Instant.now().minusSeconds(10000)))
        store.update(newInternal)
      }

      def wrongKeyAuthenticator: IO[AugmentedJWT[A, Int]] =
        authenticator.withSigningKey(macKeyGen.generateKey).create(123)
    }
  }

  /** Stateful arbitrary header tests
    *
    */
  def statefulArbitraryH[A: JWTMacAlgo: JCAMacTag](
      implicit cv: JWSMacCV[IO, A],
      macKeyGen: IdKeyGen[A, MacSigningKey],
      store: BackingStore[IO, SecureRandomId, AugmentedJWT[A, Int]]
  ): AuthSpecTester[AugmentedJWT[A, Int]] = {
    val dummyStore = dummyBackingStore[IO, Int, DummyUser](_.id)
    val macKey     = macKeyGen.generateKey
    val authenticator = JWTAuthenticator.withBackingStoreArbitrary[IO, Int, DummyUser, A](
      settings,
      store,
      dummyStore,
      macKey
    )
    new AuthSpecTester[AugmentedJWT[A, Int]](authenticator, dummyStore) {

      def embedInRequest(request: Request[IO], authenticator: AugmentedJWT[A, Int]): Request[IO] =
        request.putHeaders(Header(settings.headerName, JWTMac.toEncodedString[IO, A](authenticator.jwt)))

      def expireAuthenticator(b: AugmentedJWT[A, Int]): IO[AugmentedJWT[A, Int]] =
        for {
          newToken <- JWTMac
            .build[IO, A](
              b.jwt.body.withExpiry(Instant.now().minusSeconds(10000)),
              macKey
            )

          expired <- store.update(b.copy(jwt = newToken, expiry = Instant.now().minusSeconds(10000)))
        } yield expired

      def timeoutAuthenticator(b: AugmentedJWT[A, Int]): IO[AugmentedJWT[A, Int]] = {
        val newInternal = b.copy(lastTouched = Some(Instant.now().minusSeconds(10000)))
        store.update(newInternal)
      }

      def wrongKeyAuthenticator: IO[AugmentedJWT[A, Int]] =
        authenticator.withSigningKey(macKeyGen.generateKey).create(123)
    }
  }

  /** Unencrypted stateless in bearer tests
    *
    */
  def stateless[A: JWTMacAlgo: JCAMacTag](
      implicit cv: JWSMacCV[IO, A],
      macKeyGen: IdKeyGen[A, MacSigningKey]
  ): AuthSpecTester[AugmentedJWT[A, Int]] = {
    val dummyStore = dummyBackingStore[IO, Int, DummyUser](_.id)
    val macKey     = macKeyGen.generateKey
    val authenticator = JWTAuthenticator.stateless[IO, Int, DummyUser, A](
      settings.expiryDuration,
      settings.maxIdle,
      dummyStore,
      macKey
    )
    new AuthSpecTester[AugmentedJWT[A, Int]](authenticator, dummyStore) {

      def embedInRequest(request: Request[IO], authenticator: AugmentedJWT[A, Int]): Request[IO] =
        request.putHeaders(buildBearerAuthHeader(JWTMac.toEncodedString[IO, A](authenticator.jwt)))

      def expireAuthenticator(b: AugmentedJWT[A, Int]): IO[AugmentedJWT[A, Int]] = {
        val expiredInstant = Instant.now().minusSeconds(10000)
        for {
          newToken <- JWTMac
            .build[IO, A](b.jwt.body.withExpiry(expiredInstant), macKey)

        } yield b.copy(jwt = newToken, expiry = expiredInstant)
      }

      def timeoutAuthenticator(b: AugmentedJWT[A, Int]): IO[AugmentedJWT[A, Int]] = {
        val expiredInstant = Instant.now().minusSeconds(20000)
        for {
          newToken <- JWTMac.build[IO, A](b.jwt.body.withIAT(expiredInstant), macKey)
        } yield b.copy(jwt = newToken, lastTouched = Some(expiredInstant))
      }

      def wrongKeyAuthenticator: IO[AugmentedJWT[A, Int]] =
        authenticator.withSigningKey(macKeyGen.generateKey).create(123)
    }
  }

  /** Encrypted Stateless non-bearer tests
    *
    */
  def statelessEncrypted[A: JWTMacAlgo: JCAMacTag, E](
      implicit cv: JWSMacCV[IO, A],
      enc: AESCTR[E],
      idKeyGen: IdKeyGen[E, SecretKey],
      macKeyGen: IdKeyGen[A, MacSigningKey]
  ): AuthSpecTester[AugmentedJWT[A, Int]] = {
    implicit val instance = enc.genEncryptor[IO].unsafeRunSync()
    implicit val strategy = enc.defaultIvStrategy[IO]

    val dummyStore = dummyBackingStore[IO, Int, DummyUser](_.id)
    val macKey     = macKeyGen.generateKey
    val cryptoKey  = enc.unsafeGenerateKey
    val authenticator = JWTAuthenticator.statelessEncryptedArbitrary[IO, Int, DummyUser, A, E](
      settings,
      dummyStore,
      macKey,
      cryptoKey
    )
    new AuthSpecTester[AugmentedJWT[A, Int]](authenticator, dummyStore) {

      def embedInRequest(request: Request[IO], authenticator: AugmentedJWT[A, Int]): Request[IO] =
        request.putHeaders(Header(settings.headerName, JWTMac.toEncodedString[IO, A](authenticator.jwt)))

      def expireAuthenticator(b: AugmentedJWT[A, Int]): IO[AugmentedJWT[A, Int]] = {
        val expiredInstant = Instant.now().minusSeconds(10000)
        for {
          newToken <- JWTMac.build[IO, A](b.jwt.body.withExpiry(expiredInstant), macKey)
        } yield b.copy(jwt = newToken, expiry = expiredInstant)
      }

      def timeoutAuthenticator(b: AugmentedJWT[A, Int]): IO[AugmentedJWT[A, Int]] = {
        val expiredInstant = Instant.now().minusSeconds(20000)
        for {
          newToken <- JWTMac
            .build[IO, A](b.jwt.body.withIAT(expiredInstant), macKey)
        } yield b.copy(jwt = newToken, lastTouched = Some(expiredInstant))
      }

      def wrongKeyAuthenticator: IO[AugmentedJWT[A, Int]] =
        authenticator.withSigningKey(macKeyGen.generateKey).create(123)
    }
  }

  /** Encrypted Stateless bearer token
    *
    */
  def statelessBearerEncrypted[A: JWTMacAlgo: JCAMacTag, E](
      implicit cv: JWSMacCV[IO, A],
      enc: AESCTR[E],
      idKeyGen: IdKeyGen[E, SecretKey],
      macKeyGen: IdKeyGen[A, MacSigningKey]
  ): AuthSpecTester[AugmentedJWT[A, Int]] = {
    implicit val instance = enc.genEncryptor[IO].unsafeRunSync()
    implicit val strategy = enc.defaultIvStrategy[IO]

    val dummyStore = dummyBackingStore[IO, Int, DummyUser](_.id)
    val macKey     = macKeyGen.generateKey
    val cryptoKey  = enc.unsafeGenerateKey
    val authenticator = JWTAuthenticator.statelessEncrypted[IO, Int, DummyUser, A, E](
      settings.expiryDuration,
      settings.maxIdle,
      dummyStore,
      macKey,
      cryptoKey
    )
    new AuthSpecTester[AugmentedJWT[A, Int]](authenticator, dummyStore) {

      def embedInRequest(request: Request[IO], authenticator: AugmentedJWT[A, Int]): Request[IO] =
        request.putHeaders(buildBearerAuthHeader(JWTMac.toEncodedString[IO, A](authenticator.jwt)))

      def expireAuthenticator(b: AugmentedJWT[A, Int]): IO[AugmentedJWT[A, Int]] = {
        val expiredInstant = Instant.now().minusSeconds(10000)
        for {
          newToken <- JWTMac
            .build[IO, A](b.jwt.body.withExpiry(expiredInstant), macKey)
        } yield b.copy(jwt = newToken, expiry = expiredInstant)
      }

      def timeoutAuthenticator(b: AugmentedJWT[A, Int]): IO[AugmentedJWT[A, Int]] = {
        val expiredInstant = Instant.now().minusSeconds(20000)
        for {
          newToken <- JWTMac.build[IO, A](b.jwt.body.withIAT(expiredInstant), macKey)
        } yield b.copy(jwt = newToken, lastTouched = Some(expiredInstant))
      }

      def wrongKeyAuthenticator: IO[AugmentedJWT[A, Int]] =
        authenticator.withSigningKey(macKeyGen.generateKey).create(123)
    }
  }

}
