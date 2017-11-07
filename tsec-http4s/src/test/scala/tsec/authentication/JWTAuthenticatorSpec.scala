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

  def genStatefulAuthenticator[A: ByteEV: JWTMacAlgo: MacTag, E](
      implicit cv: JWSMacCV[IO, A],
      enc: Encryptor[E],
      eKeyGen: CipherKeyGen[E],
      macKeyGen: MacKeyGenerator[A],
      store: BackingStore[IO, SecureRandomId, JWTMac[A]]
  ): AuthSpecTester[JWTMac[A]] = {
    val dummyStore = dummyBackingStore[IO, Int, DummyUser](_.id)
    val macKey     = macKeyGen.generateKeyUnsafe()
    val cryptoKey  = eKeyGen.generateKeyUnsafe()
    val auth = JWTAuthenticator.withBackingStore[IO, Int, DummyUser, A, E](
      settings,
      store,
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
          _ <- OptionT.liftF(store.update(newToken))
        } yield newToken

      def timeoutAuthenticator(b: JWTMac[A]): OptionT[IO, JWTMac[A]] =
        for {
          internal <- OptionT.fromOption[IO](b.body.custom.flatMap(_.as[JWTInternal].toOption))
          newInternal = internal.copy(lastTouched = Some(HttpDate.unsafeFromInstant(Instant.now().minusSeconds(10000))))
          newToken <- OptionT.liftF[IO, JWTMac[A]] {
            JWTMacM
              .build[IO, A](b.body.copy(custom = Some(newInternal.asJson)), macKey)
          }
          _ <- OptionT.liftF(store.update(newToken))
        } yield newToken

      def wrongKeyAuthenticator: OptionT[IO, JWTMac[A]] =
        JWTAuthenticator
          .withBackingStore[IO, Int, DummyUser, A, E](
            settings,
            store,
            dummyStore,
            macKeyGen.generateKeyUnsafe(),
            eKeyGen.generateKeyUnsafe()
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
          newInternal = internal.copy(lastTouched = Some(HttpDate.unsafeFromInstant(Instant.now().minusSeconds(20000))))
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
