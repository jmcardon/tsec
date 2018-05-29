package tsec.authentication.internal

import java.time.Instant

import cats.data.OptionT
import cats.effect.Sync
import cats.syntax.all._
import io.circe.parser.decode
import io.circe.syntax._
import io.circe.{Decoder, Encoder}
import org.http4s._
import tsec.authentication._
import tsec.common._
import tsec.jws.mac._
import tsec.jwt.algorithms.JWTMacAlgo
import tsec.jwt.{JWTClaims, JWTPrinter}
import tsec.keyrotation.KeyStrategy
import tsec.mac.jca._

import scala.concurrent.duration._

/** A JWT authenticator backed by a db copy,
  * as well as user backed in a DB
  */
private[tsec] abstract class PartialStatelessJWTAuth[F[_], I: Decoder: Encoder, V, A: JWTMacAlgo](
    val expiry: FiniteDuration,
    val maxIdle: Option[FiniteDuration],
    identityStore: IdentityStore[F, I, V],
    keyStrategy: KeyStrategy[F, MacSigningKey, A]
)(implicit F: Sync[F], cv: JWSMacCV[F, A])
    extends JWTAuthenticator[F, I, V, A] {

  private[tsec] def verifyLastTouched(body: JWTMac[A], now: Instant): F[Option[Instant]]

  def parseRaw(raw: String, request: Request[F]): OptionT[F, SecuredRequest[F, V, AugmentedJWT[A, I]]] =
    OptionT(
      (for {
        now         <- F.delay(Instant.now())
        key         <- keyStrategy.retrieveKey
        extracted   <- cv.verifyAndParse(raw, key, now)
        jwtid       <- cataOption(extracted.id)
        id          <- cataOption(extracted.body.subject.flatMap(decode[I](_).toOption))
        expiry      <- cataOption(extracted.body.expiration)
        lastTouched <- verifyLastTouched(extracted, now)
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
        expiration = Some(expiryTime)
      )
      key <- keyStrategy.retrieveKey
      out <- JWTMac.build[F, A](claims, key)
    } yield AugmentedJWT(cookieId, out, body, expiryTime, lastTouched)

  def renew(authenticator: AugmentedJWT[A, I]): F[AugmentedJWT[A, I]] =
    for {
      now <- F.delay(Instant.now())
      updatedExpiry = now.plusSeconds(expiry.toSeconds)
      authBody      = authenticator.jwt.body
      key <- keyStrategy.retrieveKey
      jwt <- JWTMac.build(
        authBody.withIAT(now).withExpiry(updatedExpiry),
        key
      )
    } yield AugmentedJWT(authenticator.id, jwt, authenticator.identity, updatedExpiry, touch(now))

  def update(authenticator: AugmentedJWT[A, I]): F[AugmentedJWT[A, I]] =
    F.pure(authenticator)

  /** The only "discarding" we can do to a stateless token is make it invalid. */
  def discard(authenticator: AugmentedJWT[A, I]): F[AugmentedJWT[A, I]] =
    for {
      now <- F.delay(Instant.now)
      //todo: cache this. There's no need to compute an invalid one.
      key <- keyStrategy.retrieveKey
      jwt <- JWTMac
        .build[F, A](
          authenticator.jwt.body
            .withExpiry(now)
            .withJwtID(SecureRandomId.Interactive.generate),
          key
        )
    } yield AugmentedJWT(authenticator.id, jwt, authenticator.identity, now, authenticator.lastTouched)
}
