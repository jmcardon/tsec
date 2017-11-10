package tsec.authentication

import java.time.Instant

import cats.{Monad, MonadError}
import cats.data.OptionT
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
import tsec.mac.imports.{MacSigningKey, MacTag}
import cats.syntax.all._
import cats.instances.string._
import scala.concurrent.duration.FiniteDuration

sealed abstract class StatefulJWTAuthenticator[F[_], I, V, A] private[tsec] (
    val expiry: FiniteDuration,
    val maxIdle: Option[FiniteDuration]
)(implicit jWSMacCV: JWSMacCV[F, A])
    extends AuthenticatorService[F, I, V, AugmentedJWT[A, I]] {
  def withSettings(settings: TSecJWTSettings): StatefulJWTAuthenticator[F, I, V, A]
  def withTokenStore(
      tokenStore: BackingStore[F, SecureRandomId, AugmentedJWT[A, I]]
  ): StatefulJWTAuthenticator[F, I, V, A]
  def withIdentityStore(identityStore: BackingStore[F, I, V]): StatefulJWTAuthenticator[F, I, V, A]
  def withSigningKey(signingKey: MacSigningKey[A]): StatefulJWTAuthenticator[F, I, V, A]
}

sealed abstract class StatelessJWTAuthenticator[F[_], I, V, A] private[tsec] (
    val expiry: FiniteDuration,
    val maxIdle: Option[FiniteDuration]
)(implicit jWSMacCV: JWSMacCV[F, A])
    extends AuthenticatorService[F, I, V, JWTMac[A]] {
  def withSettings(settings: TSecJWTSettings): StatelessJWTAuthenticator[F, I, V, A]
  def withIdentityStore(identityStore: BackingStore[F, I, V]): StatelessJWTAuthenticator[F, I, V, A]
  def withSigningKey(signingKey: MacSigningKey[A]): StatelessJWTAuthenticator[F, I, V, A]
  def withEncryptionKey[E: Encryptor](encryptionKey: SecretKey[E]): StatelessJWTAuthenticator[F, I, V, A]
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

  /** An internal class that is meant to hold the encrypted value of some arbitrary
    * custom field in a b64 string
    *
    * @param value
    * @param lastTouched
    */
  final private[authentication] case class JWTInternal(
      value: String,
      lastTouched: Option[Instant]
  ) {
    def isTimedout(now: Instant, timeOut: FiniteDuration): Boolean =
      lastTouched.exists(
        _.plusSeconds(timeOut.toSeconds)
          .isBefore(now)
      )
  }

  def withBackingStore[F[_], I: Decoder: Encoder, V, A: ByteEV: JWTMacAlgo: MacTag](
      settings: TSecJWTSettings,
      tokenStore: BackingStore[F, SecureRandomId, AugmentedJWT[A, I]],
      identityStore: BackingStore[F, I, V],
      signingKey: MacSigningKey[A]
  )(
      implicit cv: JWSMacCV[F, A],
      M: MonadError[F, Throwable]
  ): StatefulJWTAuthenticator[F, I, V, A] =
    new StatefulJWTAuthenticator[F, I, V, A](settings.expiryDuration, settings.maxIdle) {

      def withSettings(s: TSecJWTSettings): StatefulJWTAuthenticator[F, I, V, A] =
        withBackingStore(s, tokenStore, identityStore, signingKey)

      def withTokenStore(
          ts: BackingStore[F, SecureRandomId, AugmentedJWT[A, I]]
      ): StatefulJWTAuthenticator[F, I, V, A] =
        withBackingStore(settings, ts, identityStore, signingKey)

      def withIdentityStore(is: BackingStore[F, I, V]): StatefulJWTAuthenticator[F, I, V, A] =
        withBackingStore(settings, tokenStore, is, signingKey)

      def withSigningKey(sk: MacSigningKey[A]): StatefulJWTAuthenticator[F, I, V, A] =
        withBackingStore(settings, tokenStore, identityStore, sk)

      /** A conditional to check for:
        * 1. Token serialization equality. No need to verify the signature, this is done via our
        * jwt deserializer
        *
        * @param raw
        * @param retrieved
        * @return
        */
      private def verifyWithRaw(raw: String, retrieved: AugmentedJWT[A, I]) = {
        val now = Instant.now()
        JWTMacM.toEncodedString(retrieved.jwt) === raw && !maxIdle.exists(
          retrieved.isTimedout(now, _)
        ) && !retrieved.isTimedout(now, expiry)
      }

      /** Same as verify with raw, but tack on dat dere diddly OptionT.
        *
        * @param raw
        * @param retrieved
        * @param body
        * @return
        */
      private def verifyWithRawF(
          raw: String,
          retrieved: AugmentedJWT[A, I]
      ): OptionT[F, Unit] =
        if (verifyWithRaw(raw, retrieved))
          OptionT.pure(())
        else
          OptionT.none

      def tryExtractRaw(request: Request[F]): Option[String] =
        request.headers.get(CaseInsensitiveString(settings.headerName)).map(_.value)

      /** We:
        * 1. Get the encryptor instance
        * 2. extract the header
        * 3. verify and parse our jwt
        * 4. decode our token UUID
        * 5. retrieve the backing store copy
        * 6. retrieve the `Internal` instance for the encoded data
        * 7. Decode the body id.
        * 6. A lil' extra verification, for that extract sec
        * 7. refresh the token, if there is anything to refresh
        * 8. Retrieve the identity from our identity store
        *
        * @param request
        * @return
        */
      def extractAndValidate(request: Request[F]): OptionT[F, SecuredRequest[F, V, AugmentedJWT[A, I]]] =
        for {
          headerValue <- OptionT.fromOption[F](tryExtractRaw(request))
          extracted   <- OptionT.liftF(cv.verifyAndParse(headerValue, signingKey))
          retrieved   <- tokenStore.get(SecureRandomId.is.flip.coerce(extracted.id))
          _           <- verifyWithRawF(headerValue, retrieved)
          refreshed   <- refresh(retrieved)
          identity    <- identityStore.get(retrieved.identity)
        } yield SecuredRequest(request, identity, refreshed)

      def create(body: I): OptionT[F, AugmentedJWT[A, I]] = {
        val now         = Instant.now()
        val cookieId    = SecureRandomId.generate
        val expiry      = now.plusSeconds(settings.expiryDuration.toSeconds)
        val lastTouched = settings.maxIdle.map(_ => now)
        val claims = JWTClaims(
          jwtId = cookieId,
          expiration = Some(expiry.getEpochSecond)
        )
        for {
          signed  <- OptionT.liftF(JWTMacM.build[F, A](claims, signingKey))
          created <- OptionT.liftF(tokenStore.put(AugmentedJWT(cookieId, signed, body, expiry, lastTouched)))
        } yield created
      }

      def update(authenticator: AugmentedJWT[A, I]): OptionT[F, AugmentedJWT[A, I]] =
        OptionT.liftF(tokenStore.update(authenticator))

      def discard(authenticator: AugmentedJWT[A, I]): OptionT[F, AugmentedJWT[A, I]] =
        OptionT.liftF(tokenStore.delete(SecureRandomId.coerce(authenticator.id))).map(_ => authenticator)

      def renew(authenticator: AugmentedJWT[A, I]): OptionT[F, AugmentedJWT[A, I]] = {
        val now           = Instant.now()
        val updatedExpiry = now.plusSeconds(settings.expiryDuration.toSeconds)
        val newBody       = authenticator.jwt.body.copy(expiration = Some(updatedExpiry.getEpochSecond))
        (settings.maxIdle match {
          case Some(idleTime) =>
            for {
              reSigned <- OptionT.liftF(JWTMacM.build(newBody, signingKey))
              updated <- OptionT.liftF(
                tokenStore.update(authenticator.copy(jwt = reSigned, expiry = updatedExpiry, lastTouched = Some(now)))
              )
            } yield updated
          case None =>
            for {
              reSigned <- OptionT.liftF(JWTMacM.build(newBody, signingKey))
              updated <- OptionT.liftF(
                tokenStore.update(authenticator.copy(jwt = reSigned, expiry = updatedExpiry))
              )
            } yield updated
        }).handleErrorWith(_ => OptionT.none)
      }

      def refresh(authenticator: AugmentedJWT[A, I]): OptionT[F, AugmentedJWT[A, I]] =
        (settings.maxIdle match {
          case Some(idleTime) =>
            val now     = Instant.now()
            val updated = authenticator.copy(lastTouched = Some(now))
            OptionT.liftF(tokenStore.update(updated))
          case None =>
            OptionT.pure(authenticator)
        }).handleErrorWith(_ => OptionT.none[F, AugmentedJWT[A, I]])

      def embed(response: Response[F], authenticator: AugmentedJWT[A, I]): Response[F] =
        response.putHeaders(
          Header(settings.headerName, JWTMacM.toEncodedString(authenticator.jwt))
        )

      def afterBlock(response: Response[F], authenticator: AugmentedJWT[A, I]): OptionT[F, Response[F]] =
        settings.maxIdle match {
          case Some(_) =>
            OptionT.pure[F](
              response.putHeaders(
                Header(settings.headerName, JWTMacM.toEncodedString(authenticator.jwt))
              )
            )
          case None =>
            OptionT.pure[F](response)
        }

    }

  def stateless[F[_], I: Decoder: Encoder, V, A: ByteEV: JWTMacAlgo: MacTag, E](
      settings: TSecJWTSettings,
      identityStore: BackingStore[F, I, V],
      signingKey: MacSigningKey[A],
      encryptionKey: SecretKey[E]
  )(
      implicit cv: JWSMacCV[F, A],
      enc: Encryptor[E],
      M: MonadError[F, Throwable]
  ): StatelessJWTAuthenticator[F, I, V, A] =
    new StatelessJWTAuthenticator[F, I, V, A](settings.expiryDuration, settings.maxIdle) {

      def withSettings(st: TSecJWTSettings): StatelessJWTAuthenticator[F, I, V, A] =
        stateless(st, identityStore, signingKey, encryptionKey)

      def withIdentityStore(is: BackingStore[F, I, V]): StatelessJWTAuthenticator[F, I, V, A] =
        stateless(settings, is, signingKey, encryptionKey)

      def withSigningKey(sk: MacSigningKey[A]): StatelessJWTAuthenticator[F, I, V, A] =
        stateless(settings, identityStore, sk, encryptionKey)

      def withEncryptionKey[EK: Encryptor](ek: SecretKey[EK]): StatelessJWTAuthenticator[F, I, V, A] =
        stateless(settings, identityStore, signingKey, ek)

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
      private def encodeI(body: I, lastTouched: Option[Instant]): Either[CipherError, Json] =
        for {
          instance <- enc.instance
          encrypted <- instance.encrypt(
            PlainText(body.asJson.pretty(JWTPrinter).utf8Bytes),
            encryptionKey
          )
        } yield JWTInternal(encrypted.toSingleArray.toB64String, lastTouched).asJson

      /** Decode the body's internal value.
        * Such a value was encoded
        *
        * @param body
        * @param instance
        * @return
        */
      private def decodeI(body: JWTInternal, instance: EncryptorInstance[E]): F[I] =
        M.fromEither(for {
          cipherText <- enc.fromSingleArray(body.value.base64Bytes)
          decrypted  <- instance.decrypt(cipherText, encryptionKey)
          decoded    <- decode[I](decrypted.content.toUtf8String)
        } yield decoded)

      /** Same as verify, but tack on dat dere diddly OptionT.
        *
        * @param body
        * @return
        */
      private def checkTimeout(body: JWTInternal): OptionT[F, Unit] =
        if (!settings.maxIdle.exists(body.isTimedout(Instant.now(), _)))
          OptionT.pure(())
        else
          OptionT.none

      def tryExtractRaw(request: Request[F]): Option[String] =
        request.headers.get(CaseInsensitiveString(settings.headerName)).map(_.value)

      /** We:
        * 1. Get the encryptor instance
        * 2. extract the header
        * 3. verify and parse our jwt
        * 4. decode our token UUID
        * 5. retrieve the backing store copy
        * 6. retrieve the `Internal` instance for the encoded data
        * 7. Decode the body id.
        * 6. A lil' extra verification, for that extract sec
        * 7. refresh the token, if there is anything to refresh
        * 8. Retrieve the identity from our identity store
        *
        * @param request
        * @return
        */
      def extractAndValidate(request: Request[F]): OptionT[F, SecuredRequest[F, V, JWTMac[A]]] =
        for {
          encryptorInstance <- OptionT.liftF(M.fromEither(enc.instance))
          rawHeader <- OptionT.fromOption[F](
            request.headers.get(CaseInsensitiveString(settings.headerName))
          )
          extracted <- OptionT.liftF(cv.verifyAndParse(rawHeader.value, signingKey))
          internal <- OptionT.fromOption[F](
            extracted.body.custom.flatMap(_.as[JWTInternal].toOption)
          )
          _           <- checkTimeout(internal)
          decodedBody <- OptionT.liftF(decodeI(internal, encryptorInstance))
          refreshed   <- refresh(extracted)
          identity    <- identityStore.get(decodedBody)
        } yield SecuredRequest(request, identity, refreshed)

      /** Create our JWT, and in our body, put our custom claims
        *
        */
      def create(body: I): OptionT[F, JWTMac[A]] = {
        val now         = Instant.now()
        val cookieId    = SecureRandomId.generate
        val expiry      = now.plusSeconds(settings.expiryDuration.toSeconds).getEpochSecond
        val lastTouched = settings.maxIdle.map(_ => now)
        val messageBody = encodeI(body, lastTouched).toOption
        val claims = JWTClaims(
          jwtId = cookieId,
          expiration = Some(expiry),
          custom = messageBody
        )
        OptionT.liftF(JWTMacM.build[F, A](claims, signingKey))
      }

      def update(authenticator: JWTMac[A]): OptionT[F, JWTMac[A]] =
        OptionT.pure[F](authenticator)

      /** The only "discarding" we can do to a stateless token is make it invalid. */
      def discard(authenticator: JWTMac[A]): OptionT[F, JWTMac[A]] =
        OptionT
          .liftF(
            JWTMacM.build(
              authenticator.body.copy(
                expiration = Some(Instant.now().getEpochSecond),
                custom = None,
                jwtId = SecureRandomId.generate
              ),
              signingKey
            )
          )
          .handleErrorWith(_ => OptionT.none)

      def renew(authenticator: JWTMac[A]): OptionT[F, JWTMac[A]] = {
        val updatedExpiry =
          Instant.now.plusSeconds(settings.expiryDuration.toSeconds).getEpochSecond
        settings.maxIdle match {
          case Some(idleTime) =>
            val now = Instant.now()
            val updatedInternal = authenticator.body.custom
              .flatMap(
                _.as[JWTInternal]
                  .map(_.copy(lastTouched = Some(now)).asJson)
                  .toOption
              )
            OptionT
              .liftF(
                JWTMacM
                  .build(
                    authenticator.body
                      .copy(custom = updatedInternal, expiration = Some(updatedExpiry)),
                    signingKey
                  )
              )
              .handleErrorWith(_ => OptionT.none)
          case None =>
            OptionT
              .liftF(
                JWTMacM
                  .build(authenticator.body.copy(expiration = Some(updatedExpiry)), signingKey)
              )
        }
      }

      def refresh(authenticator: JWTMac[A]): OptionT[F, JWTMac[A]] = settings.maxIdle match {
        case Some(_) =>
          val now = Instant.now()
          val updatedInternal = authenticator.body.custom
            .flatMap(
              _.as[JWTInternal]
                .map(_.copy(lastTouched = Some(now)).asJson)
                .toOption
            )
          OptionT
            .liftF(JWTMacM.build(authenticator.body.copy(custom = updatedInternal), signingKey))
            .handleErrorWith(_ => OptionT.none)
        case None =>
          OptionT.pure[F](authenticator)
      }

      def embed(response: Response[F], authenticator: JWTMac[A]): Response[F] =
        response.copy[F](
          headers = response.headers.put(
            Header(settings.headerName, JWTMacM.toEncodedString(authenticator))
          )
        )

      def afterBlock(response: Response[F], authenticator: JWTMac[A]): OptionT[F, Response[F]] =
        settings.maxIdle match {
          case Some(_) =>
            OptionT.pure[F](
              response.copy[F](
                headers = response.headers.put(
                  Header(settings.headerName, JWTMacM.toEncodedString(authenticator))
                )
              )
            )
          case None =>
            OptionT.pure[F](response)
        }
    }

}
