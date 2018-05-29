package tsec.authentication.internal

import java.time.Instant

import cats.data.OptionT
import cats.effect.Sync
import cats.syntax.all._
import io.circe.syntax._
import io.circe.{Decoder, ObjectEncoder}
import org.http4s._
import tsec.authentication._
import tsec.common._
import tsec.jws.mac._
import tsec.jwt.algorithms.JWTMacAlgo
import tsec.jwt.JWTClaims
import tsec.keyrotation.KeyStrategy
import tsec.mac.MAC
import tsec.mac.jca._

import scala.concurrent.duration._

private[tsec] abstract class StatelessJWTAuth[F[_], V: Decoder: ObjectEncoder, A: JWTMacAlgo](
    val expiry: FiniteDuration,
    val maxIdle: Option[FiniteDuration],
    keyStrategy: KeyStrategy[F, MacSigningKey, A]
)(implicit F: Sync[F], cv: JWSMacCV[F, A])
    extends JWTAuthenticator[F, V, V, A] {

  private[tsec] def verifyLastTouched(body: JWTMac[A], now: Instant): F[Option[Instant]]

  def parseRaw(raw: String, request: Request[F]): OptionT[F, SecuredRequest[F, V, AugmentedJWT[A, V]]] =
    OptionT(
      (for {
        now         <- F.delay(Instant.now())
        key         <- keyStrategy.retrieveKey
        extracted   <- cv.verifyAndParse(raw, key, now)
        jwtid       <- cataOption(extracted.id)
        body        <- extracted.body.asF[F, V]
        expiry      <- cataOption(extracted.body.expiration)
        lastTouched <- verifyLastTouched(extracted, now)
        augmented = AugmentedJWT(
          SecureRandomId.coerce(jwtid),
          extracted,
          body,
          expiry,
          lastTouched
        )
        refreshed <- refresh(augmented)
      } yield SecuredRequest(request, body, refreshed).some)
        .handleError(_ => None)
    )

  def create(body: V): F[AugmentedJWT[A, V]] =
    for {
      now   <- F.delay(Instant.now())
      jwtId <- SecureRandomId.Interactive.generateF[F]
      expiryTime  = now.plusSeconds(expiry.toSeconds)
      lastTouched = touch(now)
      claims = JWTClaims(
        issuedAt = touch(now),
        jwtId = Some(jwtId),
        expiration = Some(expiryTime),
        customFields = body.asJsonObject.toList
      )
      key <- keyStrategy.retrieveKey
      out <- JWTMac.build[F, A](claims, key)
    } yield AugmentedJWT(jwtId, out, body, expiryTime, lastTouched)

  def update(authenticator: AugmentedJWT[A, V]): F[AugmentedJWT[A, V]] =
    F.pure(authenticator)

  def renew(authenticator: AugmentedJWT[A, V]): F[AugmentedJWT[A, V]] =
    for {
      now <- F.delay(Instant.now())
      updatedExpiry = now.plusSeconds(expiry.toSeconds)
      authBody      = authenticator.jwt.body
      lastTouched   = touch(now)
      key <- keyStrategy.retrieveKey
      jwt <- JWTMac.build(
        authBody.withIATOption(lastTouched).withExpiry(updatedExpiry),
        key
      )
    } yield AugmentedJWT(authenticator.id, jwt, authenticator.identity, updatedExpiry, lastTouched)

  //Todo: Cache this, there's no need to recompute
  def discard(authenticator: AugmentedJWT[A, V]): F[AugmentedJWT[A, V]] =
    F.pure(authenticator.copy(jwt = JWTMac.buildToken[A](JWSMacHeader[A], JWTClaims(), MAC[A](Array.empty[Byte]))))

  def afterBlock(response: Response[F], authenticator: AugmentedJWT[A, V]): OptionT[F, Response[F]] =
    OptionT.pure[F](embed(response, authenticator))
}
