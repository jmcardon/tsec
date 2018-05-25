package tsec.authentication.internal

import java.time.Instant

import cats.data.OptionT
import cats.effect.Sync
import cats.syntax.all._
import org.http4s._
import tsec.authentication._
import tsec.common._
import tsec.jws.mac._
import tsec.jwt._
import tsec.jwt.algorithms.JWTMacAlgo
import tsec.keyrotation.KeyStrategy
import tsec.mac.jca._

import scala.concurrent.duration.FiniteDuration

/** A JWT authenticator backed by a db copy,
  * as well as user backed in a DB
  */
private[tsec] abstract class StatefulJWTAuth[F[_], I, V, A: JWTMacAlgo](
    val expiry: FiniteDuration,
    val maxIdle: Option[FiniteDuration],
    tokenStore: BackingStore[F, SecureRandomId, AugmentedJWT[A, I]],
    identityStore: IdentityStore[F, I, V],
    signingKey: KeyStrategy[F, MacSigningKey, A]
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
        key       <- signingKey.retrieveKey
        extracted <- cv.verifyAndParse(raw, key, now)
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
      key     <- signingKey.retrieveKey
      signed  <- JWTMac.build[F, A](claims, key)
      created <- tokenStore.put(AugmentedJWT(cookieId, signed, body, newExpiry, touch(now)))
    } yield created

  def renew(authenticator: AugmentedJWT[A, I]): F[AugmentedJWT[A, I]] =
    F.delay(Instant.now()).flatMap { now =>
      val updatedExpiry = now.plusSeconds(expiry.toSeconds)
      val newBody       = authenticator.jwt.body.withExpiry(updatedExpiry)
      for {
        key      <- signingKey.retrieveKey
        reSigned <- JWTMac.build[F, A](newBody, key)
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
