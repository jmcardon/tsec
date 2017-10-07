package tsec.auth

import java.time.Instant
import java.util.UUID

import cats.Monad
import cats.data.OptionT
import tsec.cipher.symmetric.imports.AuthEncryptor
import cats.implicits._
import tsec.common._
import tsec.messagedigests._
import tsec.messagedigests.imports._
import tsec.cookies._
import tsec.jws.mac.{JWSMacCV, JWTMac}
import tsec.mac.imports.{MacSigningKey, MacTag}
import io.circe._
import io.circe.parser.decode

import scala.concurrent.duration.FiniteDuration

/** A base typeclass for authentication
  *
  * @tparam Alg The related cryptographic algorithm used in authentication
  * @tparam I The Identifier type
  * @tparam V The value type, i.e user, or possibly only partial information
  */
sealed trait Authenticator[F[_], Alg, I, V] {
  type Authenticator[T]

  def retrieveIdentity(stringRepr: String): OptionT[F, V]

  def create(body: I): OptionT[F, Authenticator[Alg]]

  def validate(stringRepr: String): OptionT[F, Boolean]

  def renew(authenticator: Authenticator[Alg]): OptionT[F, Authenticator[Alg]]

  def update(authenticator: Authenticator[Alg]): OptionT[F, Authenticator[Alg]]

}

abstract class CookieAuthenticator[F[_], Alg: MacTag: ByteEV, I, V] extends Authenticator[F, Alg, I, V] {
  type Authenticator[T] = SignedCookie[T]
}

object CookieAuthenticator {
  final case class CookieInternal[A, Id](
      id: UUID,
      cookie: SignedCookie[A],
      messageId: Id,
      expiresAt: Instant,
      lastTouched: Option[Long]
  ) {
    def isExpired(now: Instant): Boolean = expiresAt.isBefore(now)
    def isTimedout(now: Instant, timeOut: FiniteDuration): Boolean =
      lastTouched.forall(
        lastTouched =>
          Instant
            .ofEpochSecond(lastTouched)
            .plusSeconds(timeOut.toSeconds)
            .isAfter(now)
      )
  }

  def apply[F[_]: Monad, Alg: MacTag: ByteEV, I: Decoder: Encoder, V](
      tokenStore: BackingStore[F, UUID, CookieInternal[Alg, I]],
      idStore: BackingStore[F, I, V],
      key: MacSigningKey[Alg],
      expiryDuration: FiniteDuration,
      maxIdle: Option[FiniteDuration],
  ): CookieAuthenticator[F, Alg, I, V] =
    new CookieAuthenticator[F, Alg, I, V] {
      private def generateNonce(message: String) =
        (message + Instant.now.toEpochMilli).utf8Bytes.hash[SHA1].toB64UrlString

      private def validateCookie(
          internal: CookieInternal[Alg, I],
          raw: SignedCookie[Alg],
          now: Instant
      ): OptionT[F, Unit] =
        if (internal.cookie === raw && !internal.isExpired(now) && !maxIdle.forall(internal.isTimedout(now, _)))
          OptionT.pure[F](())
        else
          OptionT.none[F, Unit]

      def retrieveIdentity(stringRepr: String): OptionT[F, V] = {
        val now     = Instant.now()
        val coerced = SignedCookie.fromRaw[Alg](stringRepr)
        for {
          original       <- OptionT.fromOption[F](CookieSigner.verifyAndRetrieve[Alg](coerced, key).toOption)
          tokenId        <- OptionT.fromOption[F](decode[UUID](original).toOption)
          cookieInternal <- tokenStore.get(tokenId)
          _              <- validateCookie(cookieInternal, coerced, now)
          message        <- idStore.get(cookieInternal.messageId)
        } yield message
      }

      def create(body: I): OptionT[F, SignedCookie[Alg]] = {
        val tokenId     = UUID.randomUUID()
        val messageBody = tokenId.toString
        val now         = Instant.now()
        val expiry      = now.plusSeconds(expiryDuration.toSeconds)
        val idleTimeout = maxIdle.map(f => now.plusSeconds(f.toSeconds).getEpochSecond)
        for {
          signed <- OptionT.fromOption[F](CookieSigner.sign[Alg](messageBody, generateNonce(messageBody), key).toOption)
          _      <- OptionT.liftF(tokenStore.put(tokenId, CookieInternal(tokenId, signed, body, expiry, idleTimeout)))
        } yield signed
      }

      def validate(string: String): OptionT[F, Boolean] = {
        val rawCoerced = SignedCookie.fromRaw[Alg](string)
        for {
          original       <- OptionT.fromOption[F](CookieSigner.verifyAndRetrieve[Alg](rawCoerced, key).toOption)
          tokenId        <- OptionT.fromOption[F](decode[UUID](original).toOption)
          cookieInternal <- tokenStore.get(tokenId)
        } yield cookieInternal.cookie === rawCoerced
      }

      def renew(authenticator: SignedCookie[Alg]): OptionT[F, SignedCookie[Alg]] = {
        val now = Instant.now()
        for {
          original       <- OptionT.fromOption[F](CookieSigner.verifyAndRetrieve[Alg](authenticator, key).toOption)
          tokenId        <- OptionT.fromOption[F](decode[UUID](original).toOption)
          cookieInternal <- tokenStore.get(tokenId)
          _ <- OptionT.liftF(
            tokenStore.update(
              cookieInternal.copy(
                expiresAt = now.plusSeconds(expiryDuration.toSeconds),
                lastTouched = cookieInternal.lastTouched.map(_ => now.getEpochSecond)
              )
            )
          )
        } yield authenticator
      }

      def update(authenticator: SignedCookie[Alg]): OptionT[F, SignedCookie[Alg]] = OptionT.pure[F](authenticator)
    }
}

abstract class EncryptedCookieAuthenticator[F[_], A, I, V](implicit auth: AuthEncryptor[A])
    extends Authenticator[F, A, I, V] {
  type Authenticator[T] = AEADCookie[T]
}

abstract class JWTMacAuthenticator[F[_], A, I, V](implicit jWSMacCV: JWSMacCV[F, A]) extends Authenticator[F, A, I, V] {
  type Authenticator[T] = JWTMac[T]

}
