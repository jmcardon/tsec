package tsec.authentication

import java.time.Instant

import cats.data.OptionT
import cats.effect.Sync
import cats.instances.string._
import cats.syntax.all._
import io.circe.parser.decode
import io.circe.syntax._
import io.circe.{Decoder, Encoder}
import org.http4s.util.CaseInsensitiveString
import org.http4s.{Header, Request, Response}
import tsec.common._
import tsec.jws.mac._
import tsec.jwt.algorithms.JWTMacAlgo
import tsec.jwt.{JWTClaims, JWTPrinter}
import tsec.mac.jca.{JCAMacTag, MacSigningKey}

import scala.concurrent.duration.FiniteDuration

/**
  * Note: Not sealed in case of user-defined
  * custom behavior
  */
abstract class JWTAuthenticator[F[_]: Sync, I, V, A] extends Authenticator[F, I, V, AugmentedJWT[A, I]]

/** A JWT authenticator backed by a db copy,
  * as well as user backed in a DB
  */
private[tsec] abstract class StatefulJWTAuth[F[_], I, V, A: JWTMacAlgo](
    val expiry: FiniteDuration,
    val maxIdle: Option[FiniteDuration],
    tokenStore: BackingStore[F, SecureRandomId, AugmentedJWT[A, I]],
    identityStore: IdentityStore[F, I, V],
    signingKey: MacSigningKey[A]
)(implicit F: Sync[F], cv: JWSMacCV[F, A])
    extends JWTAuthenticator[F, I, V, A] {

  private[tsec] def verifyAndRefresh(
      raw: String,
      retrieved: AugmentedJWT[A, I],
      now: Instant
  ): F[AugmentedJWT[A, I]]

  def parseRaw(raw: String, request: Request[F]): OptionT[F, SecuredRequest[F, V, AugmentedJWT[A, I]]] =
    OptionT(
      (for {
        now       <- F.delay(Instant.now())
        extracted <- cv.verifyAndParse(raw, signingKey, now)
        id        <- cataOption(extracted.id)
        retrieved <- tokenStore.get(SecureRandomId(id)).orAuthFailure
        refreshed <- verifyAndRefresh(raw, retrieved, now)
        identity  <- identityStore.get(retrieved.identity).orAuthFailure
      } yield SecuredRequest(request, identity, refreshed).some)
        .handleError(_ => None)
    )

  def create(body: I): F[AugmentedJWT[A, I]] =
    for {
      cookieId <- F.delay(SecureRandomId.Interactive.generate)
      now      <- F.delay(Instant.now())
      newExpiry = now.plusSeconds(expiry.toSeconds)
      claims = JWTClaims(
        issuedAt = Some(now),
        jwtId = Some(cookieId),
        expiration = Some(newExpiry)
      )
      signed  <- JWTMac.build[F, A](claims, signingKey)
      created <- tokenStore.put(AugmentedJWT(cookieId, signed, body, newExpiry, touch(now)))
    } yield created

  def renew(authenticator: AugmentedJWT[A, I]): F[AugmentedJWT[A, I]] =
    F.delay(Instant.now()).flatMap { now =>
      val updatedExpiry = now.plusSeconds(expiry.toSeconds)
      val newBody       = authenticator.jwt.body.withExpiry(updatedExpiry)
      for {
        reSigned <- JWTMac.build[F, A](newBody, signingKey)
        updated <- tokenStore
          .update(authenticator.copy(jwt = reSigned, expiry = updatedExpiry, lastTouched = touch(now)))
      } yield updated
    }

  def update(authenticator: AugmentedJWT[A, I]): F[AugmentedJWT[A, I]] =
    tokenStore.update(authenticator)

  def discard(authenticator: AugmentedJWT[A, I]): F[AugmentedJWT[A, I]] =
    tokenStore.delete(SecureRandomId.coerce(authenticator.id)).map(_ => authenticator)

  def afterBlock(response: Response[F], authenticator: AugmentedJWT[A, I]): OptionT[F, Response[F]] =
    OptionT.pure[F](response)
}

/** A JWT authenticator backed by a db copy,
  * as well as user backed in a DB
  */
private[tsec] sealed abstract class PartialStatelessJWTAuth[F[_], I: Decoder: Encoder, V, A: JWTMacAlgo](
    val expiry: FiniteDuration,
    val maxIdle: Option[FiniteDuration],
    identityStore: IdentityStore[F, I, V],
    signingKey: MacSigningKey[A]
)(implicit F: Sync[F], cv: JWSMacCV[F, A])
    extends JWTAuthenticator[F, I, V, A] {

  private[tsec] def verifyLastTouched(body: JWTMac[A]): F[Option[Instant]]

  def parseRaw(raw: String, request: Request[F]): OptionT[F, SecuredRequest[F, V, AugmentedJWT[A, I]]] =
    OptionT(
      (for {
        now         <- F.delay(Instant.now())
        extracted   <- cv.verifyAndParse(raw, signingKey, now)
        jwtid       <- cataOption(extracted.id)
        id          <- cataOption(extracted.body.subject.flatMap(decode[I](_).toOption))
        expiry      <- cataOption(extracted.body.expiration)
        lastTouched <- verifyLastTouched(extracted)
        augmented = AugmentedJWT(
          SecureRandomId.coerce(jwtid),
          extracted,
          id,
          expiry,
          lastTouched
        )
        refreshed <- refresh(augmented)
        identity  <- identityStore.get(id).orAuthFailure
      } yield SecuredRequest(request, identity, refreshed).some)
        .handleError(_ => None)
    )

  def create(body: I): F[AugmentedJWT[A, I]] =
    for {
      now      <- F.delay(Instant.now())
      cookieId <- F.delay(SecureRandomId.Interactive.generate)
      expiryTime  = now.plusSeconds(expiry.toSeconds)
      lastTouched = touch(now)
      subj        = Some(body.asJson.pretty(JWTPrinter))
      claims = JWTClaims(
        issuedAt = Some(now),
        subject = subj,
        jwtId = Some(cookieId),
        expiration = Some(expiryTime),
      )
      out <- JWTMac.build[F, A](claims, signingKey)
    } yield AugmentedJWT(cookieId, out, body, expiryTime, lastTouched)

  def renew(authenticator: AugmentedJWT[A, I]): F[AugmentedJWT[A, I]] =
    for {
      now <- F.delay(Instant.now())
      updatedExpiry = now.plusSeconds(expiry.toSeconds)
      authBody      = authenticator.jwt.body
      jwt <- JWTMac.build(
        authBody.withIAT(now).withExpiry(updatedExpiry),
        signingKey
      )
    } yield AugmentedJWT(authenticator.id, jwt, authenticator.identity, updatedExpiry, touch(now))

  def update(authenticator: AugmentedJWT[A, I]): F[AugmentedJWT[A, I]] =
    F.pure(authenticator)

  /** The only "discarding" we can do to a stateless token is make it invalid. */
  def discard(authenticator: AugmentedJWT[A, I]): F[AugmentedJWT[A, I]] =
    for {
      now <- F.delay(Instant.now)
      jwt <- JWTMac
        .build[F, A](
          authenticator.jwt.body
            .withExpiry(now)
            .withJwtID(SecureRandomId.Interactive.generate),
          signingKey
        )
    } yield AugmentedJWT(authenticator.id, jwt, authenticator.identity, now, authenticator.lastTouched)
}

/** An `Authenticator` that wraps a JWTMAC[A]
  *
  */
final case class AugmentedJWT[A, I](
    id: SecureRandomId,
    jwt: JWTMac[A],
    identity: I,
    expiry: Instant,
    lastTouched: Option[Instant]
)

object AugmentedJWT {
  implicit def auth[A, I]: AuthToken[AugmentedJWT[A, I]] = new AuthToken[AugmentedJWT[A, I]] {
    def expiry(a: AugmentedJWT[A, I]): Instant = a.expiry

    def lastTouched(a: AugmentedJWT[A, I]): Option[Instant] = a.lastTouched
  }
}

object JWTAuthenticator {

  /** Create a JWT Authenticator that will transport it as a
    * bearer token
    */
  def withBackingStore[F[_], I, V, A: JWTMacAlgo: JCAMacTag](
      expiryDuration: FiniteDuration,
      maxIdle: Option[FiniteDuration],
      tokenStore: BackingStore[F, SecureRandomId, AugmentedJWT[A, I]],
      identityStore: IdentityStore[F, I, V],
      signingKey: MacSigningKey[A]
  )(implicit cv: JWSMacCV[F, A], F: Sync[F]): StatefulJWTAuth[F, I, V, A] =
    backed[F, I, V, A](
      expiryDuration,
      maxIdle,
      tokenStore,
      identityStore,
      signingKey,
      extractBearerToken[F],
      (r, a) => r.putHeaders(buildBearerAuthHeader(JWTMac.toEncodedString(a.jwt)))
    )

  /** Create a JWT Authenticator that will transport it as a
    * bearer token
    */
  private[tsec] def backed[F[_], I, V, A: JWTMacAlgo: JCAMacTag](
      expiryDuration: FiniteDuration,
      maxIdle: Option[FiniteDuration],
      tokenStore: BackingStore[F, SecureRandomId, AugmentedJWT[A, I]],
      identityStore: IdentityStore[F, I, V],
      signingKey: MacSigningKey[A],
      extract: Request[F] => Option[String],
      embedInResponse: (Response[F], AugmentedJWT[A, I]) => Response[F]
  )(implicit cv: JWSMacCV[F, A], F: Sync[F]): StatefulJWTAuth[F, I, V, A] =
    maxIdle match {
      case Some(maxIdleTime) =>
        new StatefulJWTAuth[F, I, V, A](expiryDuration, maxIdle, tokenStore, identityStore, signingKey) {

          private def verifyWithRaw(raw: String, retrieved: AugmentedJWT[A, I], now: Instant) =
            JWTMac.toEncodedString(retrieved.jwt) === raw && !retrieved.isExpired(now) &&
              !retrieved.isTimedOut(now, maxIdleTime)

          private[tsec] def verifyAndRefresh(raw: String, retrieved: AugmentedJWT[A, I], now: Instant) =
            if (verifyWithRaw(raw, retrieved, now))
              refresh(retrieved)
            else
              F.raiseError(AuthenticationFailure)

          def extractRawOption(request: Request[F]): Option[String] =
            extract(request)

          def refresh(authenticator: AugmentedJWT[A, I]): F[AugmentedJWT[A, I]] =
            F.delay(Instant.now()).flatMap { now =>
              tokenStore.update(authenticator.copy(lastTouched = Some(now)))
            }

          def embed(response: Response[F], authenticator: AugmentedJWT[A, I]): Response[F] =
            embedInResponse(response, authenticator)
        }

      case None =>
        new StatefulJWTAuth[F, I, V, A](expiryDuration, maxIdle, tokenStore, identityStore, signingKey) {

          /** A conditional to check for:
            * 1. Token serialization equality. No need to verify the signature, this is done via our
            * jwt deserializer
            *
            * @param raw
            * @param retrieved
            * @return
            */
          private def verifyWithRaw(raw: String, retrieved: AugmentedJWT[A, I], now: Instant) =
            JWTMac.toEncodedString(retrieved.jwt) === raw && !retrieved.isExpired(now)

          private[tsec] def verifyAndRefresh(raw: String, retrieved: AugmentedJWT[A, I], now: Instant) =
            if (verifyWithRaw(raw, retrieved, now))
              F.pure(retrieved)
            else
              F.raiseError(AuthenticationFailure)

          def extractRawOption(request: Request[F]): Option[String] =
            extract(request)

          def refresh(authenticator: AugmentedJWT[A, I]): F[AugmentedJWT[A, I]] =
            F.pure(authenticator)

          def embed(response: Response[F], authenticator: AugmentedJWT[A, I]): Response[F] =
            embedInResponse(response, authenticator)
        }
    }

  /** Create a JWT Authenticator that will transport it in
    * an arbitrary header, with a backing store.
    *
    */
  def withBackingStoreArbitrary[F[_], I, V, A: JWTMacAlgo: JCAMacTag](
      settings: TSecJWTSettings,
      tokenStore: BackingStore[F, SecureRandomId, AugmentedJWT[A, I]],
      identityStore: IdentityStore[F, I, V],
      signingKey: MacSigningKey[A]
  )(implicit cv: JWSMacCV[F, A], F: Sync[F]): JWTAuthenticator[F, I, V, A] =
    backed[F, I, V, A](
      settings.expiryDuration,
      settings.maxIdle,
      tokenStore,
      identityStore,
      signingKey,
      _.headers.get(CaseInsensitiveString(settings.headerName)).map(_.value),
      (r, a) => r.putHeaders(Header(settings.headerName, JWTMac.toEncodedString(a.jwt)))
    )

  /** Create a JWT Authenticator that transports the token
    * inside of the Authorization header as a bearer token,
    * and the Id type I inside of the token in the subject parameter.
    *
    * @param expiry the token expiration time
    * @param maxIdle the optional sliding window expiration
    * @param identityStore the user store
    * @param signingKey the MAC signing key
    * @tparam F Your parametrized effect type
    * @tparam I the identity type
    * @tparam V the user value type
    * @tparam A the mac signing algorithm
    * @return
    */
  def stateless[F[_], I: Decoder: Encoder, V, A: JWTMacAlgo: JCAMacTag](
      expiry: FiniteDuration,
      maxIdle: Option[FiniteDuration],
      identityStore: IdentityStore[F, I, V],
      signingKey: MacSigningKey[A],
  )(implicit cv: JWSMacCV[F, A], F: Sync[F]): JWTAuthenticator[F, I, V, A] =
    maxIdle match {
      case Some(mIdle) =>
        new PartialStatelessJWTAuth[F, I, V, A](expiry, maxIdle, identityStore, signingKey) {
          private[tsec] def verifyLastTouched(body: JWTMac[A]): F[Option[Instant]] =
            for {
              iat <- F.delay(body.body.issuedAt)
              now <- F.delay(Instant.now())
              instant <- if (!iat.exists(_.plusSeconds(mIdle.toSeconds).isBefore(now)))
                F.pure(iat)
              else
                F.raiseError(AuthenticationFailure)
            } yield instant

          def extractRawOption(request: Request[F]): Option[String] =
            extractBearerToken(request)

          def refresh(authenticator: AugmentedJWT[A, I]): F[AugmentedJWT[A, I]] =
            for {
              now      <- F.delay(Instant.now())
              newToken <- JWTMac.build(authenticator.jwt.body.withIAT(now), signingKey)
            } yield authenticator.copy(jwt = newToken, lastTouched = Some(now))

          def embed(response: Response[F], authenticator: AugmentedJWT[A, I]): Response[F] =
            response.putHeaders(buildBearerAuthHeader(JWTMac.toEncodedString(authenticator.jwt)))

          def afterBlock(response: Response[F], authenticator: AugmentedJWT[A, I]): OptionT[F, Response[F]] =
            OptionT.pure[F](
              response.putHeaders(buildBearerAuthHeader(JWTMac.toEncodedString(authenticator.jwt)))
            )
        }

      case None =>
        new PartialStatelessJWTAuth[F, I, V, A](expiry, maxIdle, identityStore, signingKey) {
          private[tsec] def verifyLastTouched(body: JWTMac[A]): F[Option[Instant]] = F.pure(None)

          def extractRawOption(request: Request[F]): Option[String] =
            extractBearerToken(request)

          def refresh(authenticator: AugmentedJWT[A, I]): F[AugmentedJWT[A, I]] =
            F.pure(authenticator)

          def embed(response: Response[F], authenticator: AugmentedJWT[A, I]): Response[F] =
            response.putHeaders(buildBearerAuthHeader(JWTMac.toEncodedString(authenticator.jwt)))

          def afterBlock(response: Response[F], authenticator: AugmentedJWT[A, I]): OptionT[F, Response[F]] =
            OptionT.pure[F](response)
        }
    }
}
