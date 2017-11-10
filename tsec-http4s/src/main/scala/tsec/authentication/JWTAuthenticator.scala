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
import cats.implicits._
import scala.concurrent.duration.FiniteDuration

sealed abstract class JWTAuthenticator[F[_], I, V, A](implicit jWSMacCV: JWSMacCV[F, A])
    extends AuthenticatorService[F, I, V, JWTMac[A]]

sealed abstract class StatefulJWTAuthenticator[F[_], I, V, A] private [tsec] (
    val expiry: FiniteDuration,
    val maxIdle: Option[FiniteDuration]
)(implicit jWSMacCV: JWSMacCV[F, A])
    extends JWTAuthenticator[F, I, V, A] {
  def withSettings(settings: TSecJWTSettings): StatefulJWTAuthenticator[F, I, V, A]
  def withTokenStore(tokenStore: BackingStore[F, SecureRandomId, JWTMac[A]]): StatefulJWTAuthenticator[F, I, V, A]
  def withIdentityStore(identityStore: BackingStore[F, I, V]): StatefulJWTAuthenticator[F, I, V, A]
  def withSigningKey(signingKey: MacSigningKey[A]): StatefulJWTAuthenticator[F, I, V, A]
  def withEncryptionKey[E: Encryptor](encryptionKey: SecretKey[E]): StatefulJWTAuthenticator[F, I, V, A]
}

sealed abstract class StatelessJWTAuthenticator[F[_], I, V, A] private[tsec]  (
    val expiry: FiniteDuration,
    val maxIdle: Option[FiniteDuration]
)(implicit jWSMacCV: JWSMacCV[F, A])
    extends JWTAuthenticator[F, I, V, A] {
  def withSettings(settings: TSecJWTSettings): StatelessJWTAuthenticator[F, I, V, A]
  def withIdentityStore(identityStore: BackingStore[F, I, V]): StatelessJWTAuthenticator[F, I, V, A]
  def withSigningKey(signingKey: MacSigningKey[A]): StatelessJWTAuthenticator[F, I, V, A]
  def withEncryptionKey[E: Encryptor](encryptionKey: SecretKey[E]): StatelessJWTAuthenticator[F, I, V, A]
}

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

  def withBackingStore[F[_], I: Decoder: Encoder, V, A: ByteEV: JWTMacAlgo: MacTag, E](
      settings: TSecJWTSettings,
      tokenStore: BackingStore[F, SecureRandomId, JWTMac[A]],
      identityStore: BackingStore[F, I, V],
      signingKey: MacSigningKey[A],
      encryptionKey: SecretKey[E]
  )(
      implicit cv: JWSMacCV[F, A],
      enc: Encryptor[E],
      M: MonadError[F, Throwable]
  ): StatefulJWTAuthenticator[F, I, V, A] =
    new StatefulJWTAuthenticator[F, I, V, A](settings.expiryDuration, settings.maxIdle) {

      def withSettings(s: TSecJWTSettings): StatefulJWTAuthenticator[F, I, V, A] =
        withBackingStore(s, tokenStore, identityStore, signingKey, encryptionKey)

      def withTokenStore(ts: BackingStore[F, SecureRandomId, JWTMac[A]]): StatefulJWTAuthenticator[F, I, V, A] =
        withBackingStore(settings, ts, identityStore, signingKey, encryptionKey)

      def withIdentityStore(is: BackingStore[F, I, V]): StatefulJWTAuthenticator[F, I, V, A] =
        withBackingStore(settings, tokenStore, is, signingKey, encryptionKey)

      def withSigningKey(sk: MacSigningKey[A]): StatefulJWTAuthenticator[F, I, V, A] =
        withBackingStore(settings, tokenStore, identityStore, sk, encryptionKey)

      def withEncryptionKey[EK: Encryptor](encryptionKey: SecretKey[EK]): StatefulJWTAuthenticator[F, I, V, A] =
        withBackingStore(settings, tokenStore, identityStore, signingKey, encryptionKey)

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

      /** A conditional to check for:
        * 1. Token serialization equality. No need to verify the signature, this is done via our
        * jwt deserializer
        * 2. check if the internal body has timed out
        *
        * @param raw
        * @param retrieved
        * @param body
        * @return
        */
      private def verifyWithRaw(raw: String, retrieved: JWTMac[A], body: JWTInternal) =
        JWTMacM.toEncodedString(retrieved) === raw && !settings.maxIdle.exists(
          body.isTimedout(Instant.now(), _)
        )

      /** Same as verify with raw, but tack on dat dere diddly OptionT.
        *
        * @param raw
        * @param retrieved
        * @param body
        * @return
        */
      private def verifyWithRawF(
          raw: String,
          retrieved: JWTMac[A],
          body: JWTInternal
      ): OptionT[F, Unit] =
        if (verifyWithRaw(raw, retrieved, body))
          OptionT.pure(())
        else
          OptionT.none

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
          retrieved <- tokenStore.get(SecureRandomId.is.flip.coerce(extracted.id))
          internal <- OptionT.fromOption[F](
            extracted.body.custom.flatMap(_.as[JWTInternal].toOption)
          )
          decodedBody <- OptionT.liftF(decodeI(internal, encryptorInstance))
          _           <- verifyWithRawF(rawHeader.value, retrieved, internal)
          refreshed   <- refresh(extracted)
          identity    <- identityStore.get(decodedBody)
        } yield SecuredRequest(request, identity, refreshed)

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
        for {
          signed <- OptionT.liftF(JWTMacM.build[F, A](claims, signingKey))
          _      <- OptionT.liftF(tokenStore.put(signed))
        } yield signed
      }

      def update(authenticator: JWTMac[A]): OptionT[F, JWTMac[A]] =
        OptionT.liftF(tokenStore.update(authenticator))

      def discard(authenticator: JWTMac[A]): OptionT[F, JWTMac[A]] =
        OptionT.liftF(tokenStore.delete(SecureRandomId.coerce(authenticator.id))).map(_ => authenticator)

      def renew(authenticator: JWTMac[A]): OptionT[F, JWTMac[A]] = {
        val now           = Instant.now()
        val updatedExpiry = now.plusSeconds(settings.expiryDuration.toSeconds).getEpochSecond
        settings.maxIdle match {
          case Some(idleTime) =>
            val updatedInternal = authenticator.body.custom
              .flatMap(
                _.as[JWTInternal]
                  .map(_.copy(lastTouched = Some(now)).asJson)
                  .toOption
              )
            for {
              reSigned <- OptionT
                .liftF(
                  JWTMacM build (authenticator.body
                    .copy(custom = updatedInternal, expiration = Some(updatedExpiry)), signingKey)
                )
                .handleErrorWith(_ => OptionT.none)
              _ <- OptionT.liftF(tokenStore.update(reSigned))
            } yield reSigned
          case None =>
            for {
              reSigned <- OptionT
                .liftF(
                  JWTMacM build (authenticator.body
                    .copy(expiration = Some(updatedExpiry)), signingKey)
                )
                .handleErrorWith(_ => OptionT.none)
              _ <- OptionT.liftF(tokenStore.update(reSigned))
            } yield reSigned
        }
      }

      def refresh(authenticator: JWTMac[A]): OptionT[F, JWTMac[A]] =
        settings.maxIdle match {
          case Some(idleTime) =>
            val now = Instant.now()
            val updatedInternal = authenticator.body.custom
              .flatMap(
                _.as[JWTInternal]
                  .map(_.copy(lastTouched = Some(now)).asJson)
                  .toOption
              )
            for {
              reSigned <- OptionT
                .liftF(JWTMacM.build(authenticator.body.copy(custom = updatedInternal), signingKey))
                .handleErrorWith(_ => OptionT.none)
              _ <- OptionT.liftF(tokenStore.update(reSigned))
            } yield reSigned
          case None =>
            OptionT.pure(authenticator)
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
