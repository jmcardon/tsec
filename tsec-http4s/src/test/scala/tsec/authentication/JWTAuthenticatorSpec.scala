package tsec.authentication

import java.time.Instant
import java.util.UUID

import cats.data.OptionT
import cats.effect.IO
import org.http4s.{Header, HttpDate, Request}
import io.circe.syntax._
import tsec.authentication.JWTAuthenticator.JWTInternal
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

  def genStatefulAuthenticator[A: ByteEV: JWTMacAlgo: MacTag](
      implicit cv: JWSMacCV[IO, A],
      macKeyGen: MacKeyGenerator[A],
      store: BackingStore[IO, SecureRandomId, AugmentedJWT[A, Int]]
  ): AuthSpecTester[AugmentedJWT[A, Int]] = {
    val dummyStore = dummyBackingStore[IO, Int, DummyUser](_.id)
    val macKey     = macKeyGen.generateKeyUnsafe()
    val auth = JWTAuthenticator.withBackingStore[IO, Int, DummyUser, A](
      settings,
      store,
      dummyStore,
      macKey
    )
    new AuthSpecTester[AugmentedJWT[A, Int]](auth, dummyStore) {

      def embedInRequest(request: Request[IO], authenticator: AugmentedJWT[A, Int]): Request[IO] =
        request.withHeaders(
          request.headers.put(Header(settings.headerName, JWTMacM.toEncodedString[IO, A](authenticator.jwt)))
        )

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
        JWTAuthenticator
          .withBackingStore[IO, Int, DummyUser, A](
            settings,
            store,
            dummyStore,
            macKeyGen.generateKeyUnsafe()
          )
          .create(123)
    }
  }

  def genStateless[A: ByteEV: JWTMacAlgo: MacTag, E](
      implicit cv: JWSMacCV[IO, A],
      enc: Encryptor[E],
      eKeyGen: CipherKeyGen[E],
      macKeyGen: MacKeyGenerator[A]
  ): AuthSpecTester[JWTMac[A]] = {
    val dummyStore = dummyBackingStore[IO, Int, DummyUser](_.id)
    val macKey     = macKeyGen.generateKeyUnsafe()
    val cryptoKey  = eKeyGen.generateKeyUnsafe()
    val auth = JWTAuthenticator.stateless[IO, Int, DummyUser, A, E](
      settings,
      dummyStore,
      macKey,
      cryptoKey
    )
    new AuthSpecTester[JWTMac[A]](auth, dummyStore) {

      def embedInRequest(request: Request[IO], authenticator: JWTMac[A]): Request[IO] =
        request.withHeaders(
          request.headers.put(Header(settings.headerName, JWTMacM.toEncodedString[IO, A](authenticator)))
        )

      def expireAuthenticator(b: JWTMac[A]): OptionT[IO, JWTMac[A]] =
        for {
          newToken <- OptionT.liftF[IO, JWTMac[A]] {
            JWTMacM
              .build[IO, A](b.body.copy(expiration = Some(Instant.now().minusSeconds(10000).getEpochSecond)), macKey)
          }
        } yield newToken

      def timeoutAuthenticator(b: JWTMac[A]): OptionT[IO, JWTMac[A]] =
        for {
          internal <- OptionT.fromOption[IO](b.body.custom.flatMap(_.as[JWTInternal].toOption))
          newInternal = internal.copy(lastTouched = Some(Instant.now().minusSeconds(20000)))
          newToken <- OptionT.liftF[IO, JWTMac[A]] {
            JWTMacM
              .build[IO, A](b.body.copy(custom = Some(newInternal.asJson)), macKey)
          }
        } yield newToken

      def wrongKeyAuthenticator: OptionT[IO, JWTMac[A]] =
        JWTAuthenticator
          .stateless[IO, Int, DummyUser, A, E](
            settings,
            dummyStore,
            macKeyGen.generateKeyUnsafe(),
            eKeyGen.generateKeyUnsafe()
          )
          .create(123)
    }
  }

}
