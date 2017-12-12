package tsec.authentication

import java.time.Instant

import cats.{Monad, MonadError}
import cats.data.OptionT
import cats.effect.Sync
import io.circe.{Decoder, Encoder, Json}
import io.circe.syntax._
import io.circe.generic.auto._
import io.circe.parser.decode
import org.http4s.util.CaseInsensitiveString
import org.http4s.{Header, HttpDate, Request, Response}
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.imports._
import tsec.common._
import tsec.jws.mac._
import tsec.jwt.{JWTClaims, JWTPrinter}
import tsec.jwt.algorithms.JWTMacAlgo
import tsec.mac.imports.MacSigningKey
import cats.syntax.all._
import cats.instances.string._
import tsec.mac.core.MacTag

import scala.concurrent.duration.FiniteDuration

sealed abstract class JWTAuthenticator[F[_]: Sync, I, V, A](implicit jWSMacCV: JWSMacCV[F, A])
    extends AuthenticatorService[F, I, V, AugmentedJWT[A, I]]

sealed abstract class StatefulJWTAuthenticator[F[_]: Sync, I, V, A] private[tsec] (
    val expiry: FiniteDuration,
    val maxIdle: Option[FiniteDuration]
)(implicit jWSMacCV: JWSMacCV[F, A])
    extends JWTAuthenticator[F, I, V, A] {
  def withSettings(settings: TSecJWTSettings): StatefulJWTAuthenticator[F, I, V, A]
  def withTokenStore(
      tokenStore: BackingStore[F, SecureRandomId, AugmentedJWT[A, I]]
  ): StatefulJWTAuthenticator[F, I, V, A]
  def withIdentityStore(identityStore: BackingStore[F, I, V]): StatefulJWTAuthenticator[F, I, V, A]
  def withSigningKey(signingKey: MacSigningKey[A]): StatefulJWTAuthenticator[F, I, V, A]
}

sealed abstract class StatelessJWTAuthenticator[F[_]: Sync, I, V, A] private[tsec] (
    val expiry: FiniteDuration,
    val maxIdle: Option[FiniteDuration]
)(implicit jWSMacCV: JWSMacCV[F, A])
    extends JWTAuthenticator[F, I, V, A] {
  def withSettings(settings: TSecJWTSettings): StatelessJWTAuthenticator[F, I, V, A]
  def withIdentityStore(identityStore: BackingStore[F, I, V]): StatelessJWTAuthenticator[F, I, V, A]
  def withSigningKey(signingKey: MacSigningKey[A]): StatelessJWTAuthenticator[F, I, V, A]
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
) extends Authenticator[I]

object JWTAuthenticator {

  /** Create a JWT Authenticator that will transport it as a
    * bearer token
    */
  def withBackingStore[F[_], I: Decoder: Encoder, V, A: JWTMacAlgo: MacTag](
      expiryDuration: FiniteDuration,
      maxIdle: Option[FiniteDuration],
      tokenStore: BackingStore[F, SecureRandomId, AugmentedJWT[A, I]],
      identityStore: BackingStore[F, I, V],
      signingKey: MacSigningKey[A]
  )(
      implicit cv: JWSMacCV[F, A],
      F: Sync[F]
  ): StatefulJWTAuthenticator[F, I, V, A] =
    new StatefulJWTAuthenticator[F, I, V, A](expiryDuration, maxIdle) {

      def withSettings(s: TSecJWTSettings): StatefulJWTAuthenticator[F, I, V, A] =
        withBackingStore(s.expiryDuration, s.maxIdle, tokenStore, identityStore, signingKey)

      def withTokenStore(
          ts: BackingStore[F, SecureRandomId, AugmentedJWT[A, I]]
      ): StatefulJWTAuthenticator[F, I, V, A] =
        withBackingStore(expiryDuration, maxIdle, ts, identityStore, signingKey)

      def withIdentityStore(is: BackingStore[F, I, V]): StatefulJWTAuthenticator[F, I, V, A] =
        withBackingStore(expiryDuration, maxIdle, tokenStore, is, signingKey)

      def withSigningKey(sk: MacSigningKey[A]): StatefulJWTAuthenticator[F, I, V, A] =
        withBackingStore(expiryDuration, maxIdle, tokenStore, identityStore, sk)

      /** A conditional to check for:
        * 1. Token serialization equality. No need to verify the signature, this is done via our
        * jwt deserializer
        *
        * @param raw
        * @param retrieved
        * @return
        */
      private def verifyWithRaw(raw: String, retrieved: AugmentedJWT[A, I], now: Instant) =
        JWTMac.toEncodedString(retrieved.jwt) === raw && !maxIdle.exists(
          retrieved.isTimedout(now, _)
        ) && !retrieved.isTimedout(now, expiry)

      private def verifyAndRefresh(
          raw: String,
          retrieved: AugmentedJWT[A, I],
          now: Instant
      ): OptionT[F, AugmentedJWT[A, I]] =
        if (verifyWithRaw(raw, retrieved, now))
          refresh(retrieved)
        else
          OptionT.none

      def extractRawOption(request: Request[F]): Option[String] =
        extractBearerToken[F](request)

      def parseRaw(raw: String, request: Request[F]): OptionT[F, SecuredRequest[F, V, AugmentedJWT[A, I]]] =
        for {
          now       <- OptionT.liftF(F.delay(Instant.now()))
          extracted <- OptionT.liftF(cv.verifyAndParse(raw, signingKey, now))
          retrieved <- tokenStore.get(SecureRandomId.is.flip.coerce(extracted.id))
          refreshed <- verifyAndRefresh(raw, retrieved, now)
          identity  <- identityStore.get(retrieved.identity)
        } yield SecuredRequest(request, identity, refreshed)

      def create(body: I): OptionT[F, AugmentedJWT[A, I]] =
        OptionT.liftF(for {
          cookieId <- F.delay(SecureRandomId.generate)
          now      <- F.delay(Instant.now())
          expiry      = now.plusSeconds(expiryDuration.toSeconds)
          lastTouched = maxIdle.map(_ => now)
          claims = JWTClaims(
            issuedAt = Some(now.getEpochSecond),
            jwtId = cookieId,
            expiration = Some(expiry.getEpochSecond)
          )
          signed  <- JWTMac.build[F, A](claims, signingKey)
          created <- tokenStore.put(AugmentedJWT(cookieId, signed, body, expiry, lastTouched))
        } yield created)

      def update(authenticator: AugmentedJWT[A, I]): OptionT[F, AugmentedJWT[A, I]] =
        OptionT.liftF(tokenStore.update(authenticator))

      def discard(authenticator: AugmentedJWT[A, I]): OptionT[F, AugmentedJWT[A, I]] =
        OptionT.liftF(tokenStore.delete(SecureRandomId.coerce(authenticator.id))).map(_ => authenticator)

      def renew(authenticator: AugmentedJWT[A, I]): OptionT[F, AugmentedJWT[A, I]] =
        OptionT
          .liftF(F.delay(Instant.now()).flatMap { now =>
            val updatedExpiry = now.plusSeconds(expiryDuration.toSeconds)
            val newBody       = authenticator.jwt.body.copy(expiration = Some(updatedExpiry.getEpochSecond))
            maxIdle match {
              case Some(idleTime) =>
                for {
                  reSigned <- JWTMac.build(newBody, signingKey)
                  updated <- tokenStore
                    .update(authenticator.copy(jwt = reSigned, expiry = updatedExpiry, lastTouched = Some(now)))
                } yield updated
              case None =>
                for {
                  reSigned <- JWTMac.build(newBody, signingKey)
                  updated  <- tokenStore.update(authenticator.copy(jwt = reSigned, expiry = updatedExpiry))
                } yield updated
            }
          })
          .handleErrorWith(_ => OptionT.none)

      def refresh(authenticator: AugmentedJWT[A, I]): OptionT[F, AugmentedJWT[A, I]] =
        OptionT
          .liftF(F.delay(Instant.now()).flatMap { now =>
            maxIdle match {
              case Some(idleTime) =>
                val updated = authenticator.copy(lastTouched = Some(now))
                tokenStore.update(updated)
              case None =>
                F.pure(authenticator)
            }
          })
          .handleErrorWith(_ => OptionT.none[F, AugmentedJWT[A, I]])

      def embed(response: Response[F], authenticator: AugmentedJWT[A, I]): Response[F] =
        response.putHeaders(
          buildBearerAuthHeader(JWTMac.toEncodedString(authenticator.jwt))
        )

      def afterBlock(response: Response[F], authenticator: AugmentedJWT[A, I]): OptionT[F, Response[F]] =
        maxIdle match {
          case Some(_) =>
            OptionT.pure[F](
              response.putHeaders(
                buildBearerAuthHeader(JWTMac.toEncodedString(authenticator.jwt))
              )
            )
          case None =>
            OptionT.pure[F](response)
        }
    }

  /** Create a JWT Authenticator that will transport it in
    * an arbitrary header, with a backing store.
    *
    */
  def withBackingStoreArbitrary[F[_], I: Decoder: Encoder, V, A: JWTMacAlgo: MacTag](
      settings: TSecJWTSettings,
      tokenStore: BackingStore[F, SecureRandomId, AugmentedJWT[A, I]],
      identityStore: BackingStore[F, I, V],
      signingKey: MacSigningKey[A]
  )(implicit cv: JWSMacCV[F, A], F: Sync[F]): StatefulJWTAuthenticator[F, I, V, A] =
    new StatefulJWTAuthenticator[F, I, V, A](settings.expiryDuration, settings.maxIdle) {

      def withSettings(s: TSecJWTSettings): StatefulJWTAuthenticator[F, I, V, A] =
        withBackingStoreArbitrary(s, tokenStore, identityStore, signingKey)

      def withTokenStore(
          ts: BackingStore[F, SecureRandomId, AugmentedJWT[A, I]]
      ): StatefulJWTAuthenticator[F, I, V, A] =
        withBackingStoreArbitrary(settings, ts, identityStore, signingKey)

      def withIdentityStore(is: BackingStore[F, I, V]): StatefulJWTAuthenticator[F, I, V, A] =
        withBackingStoreArbitrary(settings, tokenStore, is, signingKey)

      def withSigningKey(sk: MacSigningKey[A]): StatefulJWTAuthenticator[F, I, V, A] =
        withBackingStoreArbitrary(settings, tokenStore, identityStore, sk)

      /** A conditional to check for:
        * 1. Token serialization equality. No need to verify the signature, this is done via our
        * jwt deserializer
        *
        * @param raw
        * @param retrieved
        * @return
        */
      private def verifyWithRaw(raw: String, retrieved: AugmentedJWT[A, I], now: Instant) =
        JWTMac.toEncodedString(retrieved.jwt) === raw && !maxIdle.exists(
          retrieved.isTimedout(now, _)
        ) && !retrieved.isTimedout(now, expiry)

      private def verifyAndRefresh(
          raw: String,
          retrieved: AugmentedJWT[A, I],
          now: Instant
      ): OptionT[F, AugmentedJWT[A, I]] =
        if (verifyWithRaw(raw, retrieved, now))
          refresh(retrieved)
        else
          OptionT.none

      def extractRawOption(request: Request[F]): Option[String] =
        request.headers.get(CaseInsensitiveString(settings.headerName)).map(_.value)

      def parseRaw(raw: String, request: Request[F]): OptionT[F, SecuredRequest[F, V, AugmentedJWT[A, I]]] =
        for {
          now       <- OptionT.liftF(F.delay(Instant.now()))
          extracted <- OptionT.liftF(cv.verifyAndParse(raw, signingKey, now))
          retrieved <- tokenStore.get(SecureRandomId.is.flip.coerce(extracted.id))
          refreshed <- verifyAndRefresh(raw, retrieved, now)
          identity  <- identityStore.get(retrieved.identity)
        } yield SecuredRequest(request, identity, refreshed)

      def create(body: I): OptionT[F, AugmentedJWT[A, I]] =
        OptionT.liftF(for {
          cookieId <- F.delay(SecureRandomId.generate)
          now      <- F.delay(Instant.now())
          expiry      = now.plusSeconds(settings.expiryDuration.toSeconds)
          lastTouched = settings.maxIdle.map(_ => now)
          claims = JWTClaims(
            jwtId = cookieId,
            expiration = Some(expiry.getEpochSecond)
          )
          signed  <- JWTMac.build[F, A](claims, signingKey)
          created <- tokenStore.put(AugmentedJWT(cookieId, signed, body, expiry, lastTouched))
        } yield created)

      def update(authenticator: AugmentedJWT[A, I]): OptionT[F, AugmentedJWT[A, I]] =
        OptionT.liftF(tokenStore.update(authenticator))

      def discard(authenticator: AugmentedJWT[A, I]): OptionT[F, AugmentedJWT[A, I]] =
        OptionT.liftF(tokenStore.delete(SecureRandomId.coerce(authenticator.id))).map(_ => authenticator)

      def renew(authenticator: AugmentedJWT[A, I]): OptionT[F, AugmentedJWT[A, I]] =
        OptionT
          .liftF(F.delay(Instant.now()).flatMap { now =>
            val updatedExpiry = now.plusSeconds(settings.expiryDuration.toSeconds)
            val newBody       = authenticator.jwt.body.copy(expiration = Some(updatedExpiry.getEpochSecond))
            settings.maxIdle match {
              case Some(idleTime) =>
                for {
                  reSigned <- JWTMac.build(newBody, signingKey)
                  updated <- tokenStore
                    .update(authenticator.copy(jwt = reSigned, expiry = updatedExpiry, lastTouched = Some(now)))
                } yield updated
              case None =>
                for {
                  reSigned <- JWTMac.build(newBody, signingKey)
                  updated  <- tokenStore.update(authenticator.copy(jwt = reSigned, expiry = updatedExpiry))
                } yield updated
            }
          })
          .handleErrorWith(_ => OptionT.none)

      def refresh(authenticator: AugmentedJWT[A, I]): OptionT[F, AugmentedJWT[A, I]] =
        settings.maxIdle match {
          case Some(idleTime) =>
            OptionT.liftF(for {
              n <- F.delay(Instant.now())
              u = authenticator.copy(lastTouched = Some(n))
              updated <- tokenStore.update(u)
            } yield updated)
          case None =>
            OptionT.pure(authenticator)
        }

      def embed(response: Response[F], authenticator: AugmentedJWT[A, I]): Response[F] =
        response.putHeaders(
          Header(settings.headerName, JWTMac.toEncodedString(authenticator.jwt))
        )

      def afterBlock(response: Response[F], authenticator: AugmentedJWT[A, I]): OptionT[F, Response[F]] =
        settings.maxIdle match {
          case Some(_) =>
            OptionT.pure[F](
              response.putHeaders(
                Header(settings.headerName, JWTMac.toEncodedString(authenticator.jwt))
              )
            )
          case None =>
            OptionT.pure[F](response)
        }

    }

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
  def stateless[F[_], I: Decoder: Encoder, V, A: JWTMacAlgo: MacTag](
      expiry: FiniteDuration,
      maxIdle: Option[FiniteDuration],
      identityStore: BackingStore[F, I, V],
      signingKey: MacSigningKey[A],
  )(implicit cv: JWSMacCV[F, A], F: Sync[F]): StatelessJWTAuthenticator[F, I, V, A] =
    new StatelessJWTAuthenticator[F, I, V, A](expiry, maxIdle) {

      def withSettings(st: TSecJWTSettings): StatelessJWTAuthenticator[F, I, V, A] =
        stateless(st.expiryDuration, st.maxIdle, identityStore, signingKey)

      def withIdentityStore(is: BackingStore[F, I, V]): StatelessJWTAuthenticator[F, I, V, A] =
        stateless(expiry, maxIdle, is, signingKey)

      def withSigningKey(sk: MacSigningKey[A]): StatelessJWTAuthenticator[F, I, V, A] =
        stateless(expiry, maxIdle, identityStore, sk)

      private def verify(body: JWTMac[A]): OptionT[F, Option[Instant]] = maxIdle match {
        case Some(max) =>
          for {
            iat <- OptionT.liftF(F.delay(body.body.issuedAt.map(Instant.ofEpochSecond)))
            now <- OptionT.liftF(F.delay(Instant.now()))
            instant <- if (!iat.exists(_.plusSeconds(max.toSeconds).isBefore(now)))
              OptionT.pure(iat)
            else
              OptionT.none
          } yield instant

        case None =>
          OptionT.pure(None)

      }

      def extractRawOption(request: Request[F]): Option[String] =
        extractBearerToken(request)

      def parseRaw(raw: String, request: Request[F]): OptionT[F, SecuredRequest[F, V, AugmentedJWT[A, I]]] =
        for {
          now         <- OptionT.liftF(F.delay(Instant.now()))
          extracted   <- OptionT.liftF(cv.verifyAndParse(raw, signingKey, now))
          id          <- OptionT.fromOption[F](extracted.body.subject.flatMap(decode[I](_).toOption))
          expiry      <- OptionT.fromOption(extracted.body.expiration)
          lastTouched <- verify(extracted)
          augmented = AugmentedJWT(
            SecureRandomId.coerce(extracted.body.jwtId),
            extracted,
            id,
            Instant.ofEpochSecond(expiry),
            lastTouched
          )
          refreshed <- refresh(augmented)
          identity  <- identityStore.get(id)
        } yield SecuredRequest(request, identity, refreshed)

      def create(body: I): OptionT[F, AugmentedJWT[A, I]] =
        OptionT.liftF(for {
          now      <- F.delay(Instant.now())
          cookieId <- F.delay(SecureRandomId.generate)
          expiryTime  = now.plusSeconds(expiry.toSeconds)
          lastTouched = maxIdle.map(_ => now)
          subj        = Some(body.asJson.pretty(JWTPrinter))
          claims = JWTClaims(
            issuedAt = Some(now.getEpochSecond),
            subject = subj,
            jwtId = cookieId,
            expiration = Some(expiryTime.getEpochSecond),
          )
          out <- JWTMac.build[F, A](claims, signingKey)
        } yield AugmentedJWT(cookieId, out, body, expiryTime, lastTouched))

      def update(authenticator: AugmentedJWT[A, I]): OptionT[F, AugmentedJWT[A, I]] =
        OptionT.pure[F](authenticator)

      /** The only "discarding" we can do to a stateless token is make it invalid. */
      def discard(authenticator: AugmentedJWT[A, I]): OptionT[F, AugmentedJWT[A, I]] =
        OptionT
          .liftF(for {
            now <- F.delay(Instant.now)
            jwt <- JWTMac.build(
              authenticator.jwt.body.copy(
                expiration = Some(now.getEpochSecond),
                custom = None,
                jwtId = SecureRandomId.generate
              ),
              signingKey
            )
          } yield AugmentedJWT(authenticator.id, jwt, authenticator.identity, now, authenticator.lastTouched))
          .handleErrorWith(_ => OptionT.none)

      def renew(authenticator: AugmentedJWT[A, I]): OptionT[F, AugmentedJWT[A, I]] =
        OptionT
          .liftF(for {
            now <- F.delay(Instant.now())
            updatedExpiry = now.plusSeconds(expiry.toSeconds)
            authBody      = authenticator.jwt.body
            jwt <- JWTMac.build(
              authBody.copy(issuedAt = Some(now.getEpochSecond), expiration = Some(updatedExpiry.getEpochSecond)),
              signingKey
            )
            aug = maxIdle match {
              case Some(_) =>
                AugmentedJWT(authenticator.id, jwt, authenticator.identity, updatedExpiry, Some(now))
              case None =>
                AugmentedJWT(authenticator.id, jwt, authenticator.identity, updatedExpiry, None)
            }
          } yield aug)
          .handleErrorWith(_ => OptionT.none)

      def refresh(authenticator: AugmentedJWT[A, I]): OptionT[F, AugmentedJWT[A, I]] = maxIdle match {
        case Some(_) =>
          OptionT
            .liftF(for {
              now      <- F.delay(Instant.now())
              newToken <- JWTMac.build(authenticator.jwt.body.copy(issuedAt = Some(now.getEpochSecond)), signingKey)
            } yield authenticator.copy(jwt = newToken, lastTouched = Some(now)))
            .handleErrorWith(_ => OptionT.none)
        case None =>
          OptionT.pure[F](authenticator)
      }

      def embed(response: Response[F], authenticator: AugmentedJWT[A, I]): Response[F] =
        response.putHeaders(buildBearerAuthHeader(JWTMac.toEncodedString(authenticator.jwt)))

      def afterBlock(response: Response[F], authenticator: AugmentedJWT[A, I]): OptionT[F, Response[F]] =
        maxIdle match {
          case Some(_) =>
            OptionT.pure[F](
              response.putHeaders(buildBearerAuthHeader(JWTMac.toEncodedString(authenticator.jwt)))
            )
          case None =>
            OptionT.pure[F](response)
        }

    }

  /** Create a stateless JWT authenticator that is transported in the
    * Authorization header as a bearer token.
    *
    * The Id type of the user is encrypted.
    *
    * @param expiryDuration the amount of time until a token expires
    * @param maxIdle an optional parameter which will indicate sliding window expiration
    * @param identityStore the user store
    * @param signingKey the mac signin gkey
    * @param encryptionKey
    * @param cv
    * @param enc
    * @param F
    * @tparam F
    * @tparam I
    * @tparam V
    * @tparam A
    * @tparam E
    * @return
    */
  def statelessEncrypted[F[_], I: Decoder: Encoder, V, A: JWTMacAlgo: MacTag, E](
      expiryDuration: FiniteDuration,
      maxIdle: Option[FiniteDuration],
      identityStore: BackingStore[F, I, V],
      signingKey: MacSigningKey[A],
      encryptionKey: SecretKey[E]
  )(implicit cv: JWSMacCV[F, A], enc: Encryptor[E], F: Sync[F]): StatelessJWTAuthenticator[F, I, V, A] =
    new StatelessJWTAuthenticator[F, I, V, A](expiryDuration, maxIdle) {

      def withSettings(st: TSecJWTSettings): StatelessJWTAuthenticator[F, I, V, A] =
        statelessEncrypted(st.expiryDuration, st.maxIdle, identityStore, signingKey, encryptionKey)

      def withIdentityStore(is: BackingStore[F, I, V]): StatelessJWTAuthenticator[F, I, V, A] =
        statelessEncrypted(expiryDuration, maxIdle, is, signingKey, encryptionKey)

      def withSigningKey(sk: MacSigningKey[A]): StatelessJWTAuthenticator[F, I, V, A] =
        statelessEncrypted(expiryDuration, maxIdle, identityStore, sk, encryptionKey)

      def withEncryptionKey[EK: Encryptor](ek: SecretKey[EK]): StatelessJWTAuthenticator[F, I, V, A] =
        statelessEncrypted(expiryDuration, maxIdle, identityStore, signingKey, ek)

      /** Generate a message body, with some arbitrary I which signal an id,
        * the possible sliding window expiration last touched time, and the default CTR encryptor
        *
        * The body is encrypted by encoding it to json, pretty printing it with our nospaces, no nulls printer,
        * then retrieving the utf8 bytes.
        * After encryption, the body bytes are encoded as a base 64 string
        *
        * @param body
        * @param lastTouched
        * @return
        */
      private def encryptIdentity(body: I, lastTouched: Option[Instant]): Either[CipherError, String] =
        for {
          instance <- enc.instance
          encrypted <- instance.encrypt(
            PlainText(body.asJson.pretty(JWTPrinter).utf8Bytes),
            encryptionKey
          )
        } yield encrypted.toSingleArray.toB64String

      /** Decode the body's internal value.
        * Such a value was encoded
        *
        * @param body
        * @param instance
        * @return
        */
      private def decryptIdentity(body: String, instance: EncryptorInstance[E]): F[I] =
        F.fromEither(for {
          cipherText <- enc.fromSingleArray(body.base64Bytes)
          decrypted  <- instance.decrypt(cipherText, encryptionKey)
          decoded    <- decode[I](decrypted.content.toUtf8String)
        } yield decoded)

      private def checkTimeout(timeout: Option[Instant]): OptionT[F, Option[Instant]] =
        for {
          now <- OptionT.liftF(F.delay(Instant.now()))
          t <- if (!maxIdle.exists(t => timeout.exists(_.plusSeconds(t.toSeconds).isBefore(now))))
            OptionT.pure(timeout)
          else
            OptionT.none
        } yield t

      def extractRawOption(request: Request[F]): Option[String] =
        extractBearerToken[F](request)

      def parseRaw(raw: String, request: Request[F]): OptionT[F, SecuredRequest[F, V, AugmentedJWT[A, I]]] =
        for {
          eInstance   <- OptionT.liftF(F.fromEither(enc.instance))
          now         <- OptionT.liftF(F.delay(Instant.now))
          extracted   <- OptionT.liftF(cv.verifyAndParse(raw, signingKey, now))
          rawId       <- OptionT.fromOption[F](extracted.body.subject)
          lastTouched <- checkTimeout(extracted.body.issuedAt.map(Instant.ofEpochSecond))
          decodedBody <- OptionT.liftF(decryptIdentity(rawId, eInstance))
          expiry      <- OptionT.fromOption(extracted.body.expiration)
          augmented = AugmentedJWT(
            SecureRandomId.coerce(extracted.body.jwtId),
            extracted,
            decodedBody,
            Instant.ofEpochSecond(expiry),
            lastTouched
          )
          refreshed <- refresh(augmented)
          identity  <- identityStore.get(decodedBody)
        } yield SecuredRequest(request, identity, refreshed)

      def create(body: I): OptionT[F, AugmentedJWT[A, I]] =
        OptionT.liftF(for {
          cookieId <- F.delay(SecureRandomId.generate)
          now      <- F.delay(Instant.now())
          expiry      = now.plusSeconds(expiryDuration.toSeconds)
          lastTouched = maxIdle.map(_ => now)
          messageBody = encryptIdentity(body, lastTouched).toOption
          claims = JWTClaims(
            issuedAt = Some(now.getEpochSecond),
            subject = messageBody,
            jwtId = cookieId,
            expiration = Some(expiry.getEpochSecond),
          )
          jwt <- JWTMac.build[F, A](claims, signingKey)
        } yield AugmentedJWT(cookieId, jwt, body, expiry, lastTouched))

      def update(authenticator: AugmentedJWT[A, I]): OptionT[F, AugmentedJWT[A, I]] =
        OptionT.pure[F](authenticator)

      /** The only "discarding" we can do to a stateless token is make it invalid. */
      def discard(authenticator: AugmentedJWT[A, I]): OptionT[F, AugmentedJWT[A, I]] =
        OptionT.liftF(for {
          now <- F.delay(Instant.now())
          jwt <- JWTMac.build(
            authenticator.jwt.body.copy(
              expiration = Some(now.getEpochSecond),
              custom = None,
              jwtId = SecureRandomId.generate
            ),
            signingKey
          )
        } yield AugmentedJWT(authenticator.id, jwt, authenticator.identity, now, authenticator.lastTouched))

      def renew(authenticator: AugmentedJWT[A, I]): OptionT[F, AugmentedJWT[A, I]] =
        OptionT
          .liftF(F.delay(Instant.now()).flatMap { now =>
            val updatedExpiry = now.plusSeconds(expiryDuration.toSeconds)
            maxIdle match {
              case Some(_) =>
                JWTMac
                  .build(
                    authenticator.jwt.body
                      .copy(expiration = Some(updatedExpiry.getEpochSecond), issuedAt = Some(now.getEpochSecond)),
                    signingKey
                  )
                  .map(AugmentedJWT(authenticator.id, _, authenticator.identity, updatedExpiry, Some(now)))
              case None =>
                JWTMac
                  .build(authenticator.jwt.body.copy(expiration = Some(updatedExpiry.getEpochSecond)), signingKey)
                  .map(AugmentedJWT(authenticator.id, _, authenticator.identity, updatedExpiry, None))
            }
          })
          .handleErrorWith(_ => OptionT.none)

      def refresh(authenticator: AugmentedJWT[A, I]): OptionT[F, AugmentedJWT[A, I]] = maxIdle match {
        case Some(_) =>
          OptionT.liftF(for {
            now <- F.delay(Instant.now())
            jwt <- JWTMac.build(authenticator.jwt.body.copy(issuedAt = Some(now.getEpochSecond)), signingKey)
          } yield authenticator.copy(jwt = jwt, lastTouched = Some(now)))

        case None =>
          OptionT.pure[F](authenticator)
      }

      def embed(response: Response[F], authenticator: AugmentedJWT[A, I]): Response[F] =
        response.putHeaders(buildBearerAuthHeader(JWTMac.toEncodedString(authenticator.jwt)))

      def afterBlock(response: Response[F], authenticator: AugmentedJWT[A, I]): OptionT[F, Response[F]] =
        maxIdle match {
          case Some(_) =>
            OptionT.pure[F](
              response.putHeaders(
                buildBearerAuthHeader(JWTMac.toEncodedString(authenticator.jwt))
              )
            )
          case None =>
            OptionT.pure[F](response)
        }

    }

  /** Create a JWT with an encrypted user Id in the `subject` claim,
    * transported in an arbitrary header
    *
    */
  def statelessEncryptedArbitrary[F[_], I: Decoder: Encoder, V, A: JWTMacAlgo: MacTag, E](
      settings: TSecJWTSettings,
      identityStore: BackingStore[F, I, V],
      signingKey: MacSigningKey[A],
      encryptionKey: SecretKey[E]
  )(implicit cv: JWSMacCV[F, A], enc: Encryptor[E], F: Sync[F]): StatelessJWTAuthenticator[F, I, V, A] =
    new StatelessJWTAuthenticator[F, I, V, A](settings.expiryDuration, settings.maxIdle) {

      def withSettings(st: TSecJWTSettings): StatelessJWTAuthenticator[F, I, V, A] =
        statelessEncryptedArbitrary(st, identityStore, signingKey, encryptionKey)

      def withIdentityStore(is: BackingStore[F, I, V]): StatelessJWTAuthenticator[F, I, V, A] =
        statelessEncryptedArbitrary(settings, is, signingKey, encryptionKey)

      def withSigningKey(sk: MacSigningKey[A]): StatelessJWTAuthenticator[F, I, V, A] =
        statelessEncryptedArbitrary(settings, identityStore, sk, encryptionKey)

      def withEncryptionKey[EK: Encryptor](ek: SecretKey[EK]): StatelessJWTAuthenticator[F, I, V, A] =
        statelessEncryptedArbitrary(settings, identityStore, signingKey, ek)

      /** Generate a message body, with some arbitrary I which signal an id,
        * the possible sliding window expiration last touched time, and the default CTR encryptor
        *
        * The body is encrypted by encoding it to json, pretty printing it with our nospaces, no nulls printer,
        * then retrieving the utf8 bytes.
        * After encryption, the body bytes are encoded as a base 64 string
        *
        * @param body
        * @param lastTouched
        * @return
        */
      private def encryptIdentity(body: I, lastTouched: Option[Instant]): Either[CipherError, String] =
        for {
          instance <- enc.instance
          encrypted <- instance.encrypt(
            PlainText(body.asJson.pretty(JWTPrinter).utf8Bytes),
            encryptionKey
          )
        } yield encrypted.toSingleArray.toB64String

      /** Decode the body's internal Id type value **/
      private def decryptIdentity(body: String, instance: EncryptorInstance[E]): F[I] =
        F.fromEither(for {
          cipherText <- enc.fromSingleArray(body.base64Bytes)
          decrypted  <- instance.decrypt(cipherText, encryptionKey)
          decoded    <- decode[I](decrypted.content.toUtf8String)
        } yield decoded)

      private def checkTimeout(timeout: Option[Instant]): OptionT[F, Option[Instant]] =
        for {
          now <- OptionT.liftF(F.delay(Instant.now()))
          t <- if (!settings.maxIdle.exists(t => timeout.exists(_.plusSeconds(t.toSeconds).isBefore(now))))
            OptionT.pure(timeout)
          else
            OptionT.none
        } yield t

      def extractRawOption(request: Request[F]): Option[String] =
        request.headers.get(CaseInsensitiveString(settings.headerName)).map(_.value)

      def parseRaw(raw: String, request: Request[F]): OptionT[F, SecuredRequest[F, V, AugmentedJWT[A, I]]] =
        for {
          eInstance   <- OptionT.liftF(F.fromEither(enc.instance))
          now         <- OptionT.liftF(F.delay(Instant.now))
          extracted   <- OptionT.liftF(cv.verifyAndParse(raw, signingKey, now))
          rawId       <- OptionT.fromOption[F](extracted.body.subject)
          lastTouched <- checkTimeout(extracted.body.issuedAt.map(Instant.ofEpochSecond))
          decodedBody <- OptionT.liftF(decryptIdentity(rawId, eInstance))
          expiry      <- OptionT.fromOption(extracted.body.expiration)
          augmented = AugmentedJWT(
            SecureRandomId.coerce(extracted.body.jwtId),
            extracted,
            decodedBody,
            Instant.ofEpochSecond(expiry),
            lastTouched
          )
          refreshed <- refresh(augmented)
          identity  <- identityStore.get(decodedBody)
        } yield SecuredRequest(request, identity, refreshed)

      def create(body: I): OptionT[F, AugmentedJWT[A, I]] =
        OptionT.liftF(for {
          now      <- F.delay(Instant.now())
          cookieId <- F.delay(SecureRandomId.generate)
          expiry      = now.plusSeconds(settings.expiryDuration.toSeconds)
          lastTouched = settings.maxIdle.map(_ => now)
          messageBody = encryptIdentity(body, lastTouched).toOption
          claims = JWTClaims(
            issuedAt = Some(now.getEpochSecond),
            subject = messageBody,
            jwtId = cookieId,
            expiration = Some(expiry.getEpochSecond),
          )
          newToken <- JWTMac.build[F, A](claims, signingKey)

        } yield AugmentedJWT(cookieId, newToken, body, expiry, lastTouched))

      /** Pretty much a no-op for a stateless token **/
      def update(authenticator: AugmentedJWT[A, I]): OptionT[F, AugmentedJWT[A, I]] =
        OptionT.pure[F](authenticator)

      /** The only "discarding" we can do to a stateless token is make it invalid. **/
      def discard(authenticator: AugmentedJWT[A, I]): OptionT[F, AugmentedJWT[A, I]] =
        OptionT
          .liftF(for {
            now <- F.delay(Instant.now())
            jwt <- JWTMac.build(
              authenticator.jwt.body.copy(
                subject = None,
                expiration = Some(now.getEpochSecond),
                jwtId = SecureRandomId.generate
              ),
              signingKey
            )
          } yield AugmentedJWT(authenticator.id, jwt, authenticator.identity, now, authenticator.lastTouched))
          .handleErrorWith(_ => OptionT.none)

      def renew(authenticator: AugmentedJWT[A, I]): OptionT[F, AugmentedJWT[A, I]] =
        OptionT
          .liftF(F.delay(Instant.now()).flatMap { now =>
            val updatedExpiry = now.plusSeconds(settings.expiryDuration.toSeconds)
            settings.maxIdle match {
              case Some(idleTime) =>
                JWTMac
                  .build(
                    authenticator.jwt.body
                      .copy(expiration = Some(updatedExpiry.getEpochSecond), issuedAt = Some(now.getEpochSecond)),
                    signingKey
                  )
                  .map(AugmentedJWT(authenticator.id, _, authenticator.identity, updatedExpiry, Some(now)))
              case None =>
                JWTMac
                  .build(authenticator.jwt.body.copy(expiration = Some(updatedExpiry.getEpochSecond)), signingKey)
                  .map(AugmentedJWT(authenticator.id, _, authenticator.identity, updatedExpiry, None))
            }
          })
          .handleErrorWith(_ => OptionT.none)

      def refresh(authenticator: AugmentedJWT[A, I]): OptionT[F, AugmentedJWT[A, I]] = settings.maxIdle match {
        case Some(_) =>
          OptionT
            .liftF(for {
              now      <- F.delay(Instant.now())
              newToken <- JWTMac.build(authenticator.jwt.body.copy(issuedAt = Some(now.getEpochSecond)), signingKey)
            } yield authenticator.copy(jwt = newToken, lastTouched = Some(now)))
            .handleErrorWith(_ => OptionT.none)
        case None =>
          OptionT.pure[F](authenticator)
      }

      def embed(response: Response[F], authenticator: AugmentedJWT[A, I]): Response[F] =
        response.putHeaders(Header(settings.headerName, JWTMac.toEncodedString(authenticator.jwt)))

      def afterBlock(response: Response[F], authenticator: AugmentedJWT[A, I]): OptionT[F, Response[F]] =
        settings.maxIdle match {
          case Some(_) =>
            OptionT.pure[F](
              response.putHeaders(Header(settings.headerName, JWTMac.toEncodedString(authenticator.jwt)))
            )
          case None =>
            OptionT.pure[F](response)
        }

    }
}
