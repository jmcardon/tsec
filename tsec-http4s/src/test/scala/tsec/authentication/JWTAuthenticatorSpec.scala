package tsec.authentication

import java.time.Instant
import java.util.UUID

import cats.data.OptionT
import cats.effect.IO
import org.http4s.{Header, HttpDate, Request}
import io.circe.syntax._
import tsec.cipher.symmetric.imports.{CipherKeyGen, Encryptor}
import tsec.common.{ByteEV, SecureRandomId}
import tsec.jws.mac.{JWSMacCV, JWTMac, JWTMacM}
import tsec.jwt.algorithms.JWTMacAlgo
import tsec.mac.imports.{MacKeyGenerator, MacTag}
import io.circe.generic.auto._

import scala.collection.mutable
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
  def stateful[A: ByteEV: JWTMacAlgo: MacTag](
      implicit cv: JWSMacCV[IO, A],
      macKeyGen: MacKeyGenerator[A],
      store: BackingStore[IO, SecureRandomId, AugmentedJWT[A, Int]]
  ): AuthSpecTester[AugmentedJWT[A, Int]] = {
    val dummyStore = dummyBackingStore[IO, Int, DummyUser](_.id)
    val macKey     = macKeyGen.generateKeyUnsafe()
    val authenticator = JWTAuthenticator.withBackingStore[IO, Int, DummyUser, A](
      settings.expiryDuration,
      settings.maxIdle,
      store,
      dummyStore,
      macKey
    )

    new AuthSpecTester[AugmentedJWT[A, Int]](authenticator, dummyStore) {

      def embedInRequest(request: Request[IO], authenticator: AugmentedJWT[A, Int]): Request[IO] =
        request.putHeaders(buildBearerAuthHeader(JWTMacM.toEncodedString[IO, A](authenticator.jwt)))

      def expireAuthenticator(b: AugmentedJWT[A, Int]): OptionT[IO, AugmentedJWT[A, Int]] =
        for {
          newToken <- OptionT.liftF[IO, JWTMac[A]] {
            JWTMacM
              .build[IO, A](
                b.jwt.body.copy(expiration = Some(Instant.now().minusSeconds(10000).getEpochSecond)),
                macKey
              )
          }
          expired <- OptionT.liftF(store.update(b.copy(jwt = newToken, expiry = Instant.now().minusSeconds(10000))))
        } yield expired

      def timeoutAuthenticator(b: AugmentedJWT[A, Int]): OptionT[IO, AugmentedJWT[A, Int]] = {
        val newInternal = b.copy(lastTouched = Some(Instant.now().minusSeconds(10000)))
        OptionT.liftF(store.update(newInternal))
      }

      def wrongKeyAuthenticator: OptionT[IO, AugmentedJWT[A, Int]] =
        authenticator.withSigningKey(macKeyGen.generateKeyUnsafe()).create(123)
    }
  }

  /** Stateful arbitrary header tests
    *
    */
  def statefulArbitraryH[A: ByteEV: JWTMacAlgo: MacTag](
      implicit cv: JWSMacCV[IO, A],
      macKeyGen: MacKeyGenerator[A],
      store: BackingStore[IO, SecureRandomId, AugmentedJWT[A, Int]]
  ): AuthSpecTester[AugmentedJWT[A, Int]] = {
    val dummyStore = dummyBackingStore[IO, Int, DummyUser](_.id)
    val macKey     = macKeyGen.generateKeyUnsafe()
    val authenticator = JWTAuthenticator.withBackingStoreArbitrary[IO, Int, DummyUser, A](
      settings,
      store,
      dummyStore,
      macKey
    )
    new AuthSpecTester[AugmentedJWT[A, Int]](authenticator, dummyStore) {

      def embedInRequest(request: Request[IO], authenticator: AugmentedJWT[A, Int]): Request[IO] =
        request.putHeaders(Header(settings.headerName, JWTMacM.toEncodedString[IO, A](authenticator.jwt)))

      def expireAuthenticator(b: AugmentedJWT[A, Int]): OptionT[IO, AugmentedJWT[A, Int]] =
        for {
          newToken <- OptionT.liftF[IO, JWTMac[A]] {
            JWTMacM
              .build[IO, A](
                b.jwt.body.copy(expiration = Some(Instant.now().minusSeconds(10000).getEpochSecond)),
                macKey
              )
          }
          expired <- OptionT.liftF(store.update(b.copy(jwt = newToken, expiry = Instant.now().minusSeconds(10000))))
        } yield expired

      def timeoutAuthenticator(b: AugmentedJWT[A, Int]): OptionT[IO, AugmentedJWT[A, Int]] = {
        val newInternal = b.copy(lastTouched = Some(Instant.now().minusSeconds(10000)))
        OptionT.liftF(store.update(newInternal))
      }

      def wrongKeyAuthenticator: OptionT[IO, AugmentedJWT[A, Int]] =
        authenticator.withSigningKey(macKeyGen.generateKeyUnsafe()).create(123)
    }
  }

  /** Unencrypted stateless in bearer tests
    *
    */
  def stateless[A: ByteEV: JWTMacAlgo: MacTag](
      implicit cv: JWSMacCV[IO, A],
      macKeyGen: MacKeyGenerator[A]
  ): AuthSpecTester[AugmentedJWT[A, Int]] = {
    val dummyStore = dummyBackingStore[IO, Int, DummyUser](_.id)
    val macKey     = macKeyGen.generateKeyUnsafe()
    val authenticator = JWTAuthenticator.stateless[IO, Int, DummyUser, A](
      settings.expiryDuration,
      settings.maxIdle,
      dummyStore,
      macKey
    )
    new AuthSpecTester[AugmentedJWT[A, Int]](authenticator, dummyStore) {

      def embedInRequest(request: Request[IO], authenticator: AugmentedJWT[A, Int]): Request[IO] =
        request.putHeaders(buildBearerAuthHeader(JWTMacM.toEncodedString[IO, A](authenticator.jwt)))

      def expireAuthenticator(b: AugmentedJWT[A, Int]): OptionT[IO, AugmentedJWT[A, Int]] = {
        val expiredInstant = Instant.now().minusSeconds(10000)
        for {
          newToken <- OptionT.liftF[IO, JWTMac[A]] {
            JWTMacM
              .build[IO, A](b.jwt.body.copy(expiration = Some(expiredInstant.getEpochSecond)), macKey)
          }
        } yield b.copy(jwt = newToken, expiry = expiredInstant)
      }

      def timeoutAuthenticator(b: AugmentedJWT[A, Int]): OptionT[IO, AugmentedJWT[A, Int]] = {
        val expiredInstant = Instant.now().minusSeconds(20000)
        for {
          newToken <- OptionT.liftF[IO, JWTMac[A]] {
            JWTMacM
              .build[IO, A](b.jwt.body.copy(issuedAt = Some(expiredInstant.getEpochSecond)), macKey)
          }
        } yield b.copy(jwt = newToken, lastTouched = Some(expiredInstant))
      }

      def wrongKeyAuthenticator: OptionT[IO, AugmentedJWT[A, Int]] =
        authenticator.withSigningKey(macKeyGen.generateKeyUnsafe()).create(123)
    }
  }

  /** Encrypted Stateless non-bearer tests
    *
    */
  def statelessEncrypted[A: ByteEV: JWTMacAlgo: MacTag, E](
      implicit cv: JWSMacCV[IO, A],
      enc: Encryptor[E],
      eKeyGen: CipherKeyGen[E],
      macKeyGen: MacKeyGenerator[A]
  ): AuthSpecTester[AugmentedJWT[A, Int]] = {
    val dummyStore = dummyBackingStore[IO, Int, DummyUser](_.id)
    val macKey     = macKeyGen.generateKeyUnsafe()
    val cryptoKey  = eKeyGen.generateKeyUnsafe()
    val authenticator = JWTAuthenticator.statelessEncryptedArbitrary[IO, Int, DummyUser, A, E](
      settings,
      dummyStore,
      macKey,
      cryptoKey
    )
    new AuthSpecTester[AugmentedJWT[A, Int]](authenticator, dummyStore) {

      def embedInRequest(request: Request[IO], authenticator: AugmentedJWT[A, Int]): Request[IO] =
        request.putHeaders(Header(settings.headerName, JWTMacM.toEncodedString[IO, A](authenticator.jwt)))

      def expireAuthenticator(b: AugmentedJWT[A, Int]): OptionT[IO, AugmentedJWT[A, Int]] = {
        val expiredInstant = Instant.now().minusSeconds(10000)
        for {
          newToken <- OptionT.liftF[IO, JWTMac[A]] {
            JWTMacM
              .build[IO, A](b.jwt.body.copy(expiration = Some(expiredInstant.getEpochSecond)), macKey)
          }
        } yield b.copy(jwt = newToken, expiry = expiredInstant)
      }

      def timeoutAuthenticator(b: AugmentedJWT[A, Int]): OptionT[IO, AugmentedJWT[A, Int]] = {
        val expiredInstant = Instant.now().minusSeconds(20000)
        for {
          newToken <- OptionT.liftF[IO, JWTMac[A]] {
            JWTMacM
              .build[IO, A](b.jwt.body.copy(issuedAt = Some(expiredInstant.getEpochSecond)), macKey)
          }
        } yield b.copy(jwt = newToken, lastTouched = Some(expiredInstant))
      }

      def wrongKeyAuthenticator: OptionT[IO, AugmentedJWT[A, Int]] =
        authenticator.withSigningKey(macKeyGen.generateKeyUnsafe()).create(123)
    }
  }

  /** Encrypted Stateless bearer token
    *
    */
  def statelessBearerEncrypted[A: ByteEV: JWTMacAlgo: MacTag, E](
      implicit cv: JWSMacCV[IO, A],
      enc: Encryptor[E],
      eKeyGen: CipherKeyGen[E],
      macKeyGen: MacKeyGenerator[A]
  ): AuthSpecTester[AugmentedJWT[A, Int]] = {
    val dummyStore = dummyBackingStore[IO, Int, DummyUser](_.id)
    val macKey     = macKeyGen.generateKeyUnsafe()
    val cryptoKey  = eKeyGen.generateKeyUnsafe()
    val authenticator = JWTAuthenticator.statelessEncrypted[IO, Int, DummyUser, A, E](
      settings.expiryDuration,
      settings.maxIdle,
      dummyStore,
      macKey,
      cryptoKey
    )
    new AuthSpecTester[AugmentedJWT[A, Int]](authenticator, dummyStore) {

      def embedInRequest(request: Request[IO], authenticator: AugmentedJWT[A, Int]): Request[IO] =
        request.putHeaders(buildBearerAuthHeader(JWTMacM.toEncodedString[IO, A](authenticator.jwt)))

      def expireAuthenticator(b: AugmentedJWT[A, Int]): OptionT[IO, AugmentedJWT[A, Int]] = {
        val expiredInstant = Instant.now().minusSeconds(10000)
        for {
          newToken <- OptionT.liftF[IO, JWTMac[A]] {
            JWTMacM
              .build[IO, A](b.jwt.body.copy(expiration = Some(expiredInstant.getEpochSecond)), macKey)
          }
        } yield b.copy(jwt = newToken, expiry = expiredInstant)
      }

      def timeoutAuthenticator(b: AugmentedJWT[A, Int]): OptionT[IO, AugmentedJWT[A, Int]] = {
        val expiredInstant = Instant.now().minusSeconds(20000)
        for {
          newToken <- OptionT.liftF[IO, JWTMac[A]] {
            JWTMacM
              .build[IO, A](b.jwt.body.copy(issuedAt = Some(expiredInstant.getEpochSecond)), macKey)
          }
        } yield b.copy(jwt = newToken, lastTouched = Some(expiredInstant))
      }

      def wrongKeyAuthenticator: OptionT[IO, AugmentedJWT[A, Int]] =
        authenticator.withSigningKey(macKeyGen.generateKeyUnsafe()).create(123)
    }
  }

}
