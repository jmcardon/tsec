package tsec.authentication

import java.math.BigInteger
import java.time.{Instant, LocalDateTime}
import java.util.Base64

import cats.data.OptionT
import cats.effect.{Effect, Sync}
import cats.syntax.all._
import io.circe.Decoder
import io.circe.parser.decode
import org.http4s.headers.Authorization
import org.http4s.{AuthScheme, Credentials, EntityDecoder, Request, Response, Uri}
import tsec.common.SecureRandomId
import tsec.jws.signature.{JWSSigCV, JWTSig}
import tsec.signature.jca.{JCASigTag, SigPublicKey}

import scala.concurrent.duration.FiniteDuration

final case class AugmentedJWKS[A, I](
    id: SecureRandomId,
    jwt: JWTSig[A],
    identity: I,
    expiry: Instant,
    lastTouched: Option[Instant]
)

final case class JWK(kid: String, alg: String, kty: String, use: String, n: String, e: String)

final case class JWKS(keys: List[JWK])

class KeyRegistry[F[_], A: JCASigTag](uri: Uri, minFetchDelay: FiniteDuration)(implicit E: Effect[F]) {

  import io.circe.generic.auto._
  import org.http4s.circe._
  import org.http4s.client.blaze._
  import java.security.KeyFactory
  import java.security.spec.RSAPublicKeySpec

  implicit val jwksDecoder: EntityDecoder[F, JWKS] = jsonOf[F, JWKS]

  private var keys = Map[String, SigPublicKey[A]]()
  private var lastFetch: Option[LocalDateTime] = None

  def getPublicKey(id: String): F[Option[SigPublicKey[A]]] = {
    getKey(id).map {
      case None if shouldFetch() =>
        for {
          _      <- E.delay(println("FETCH"))
          client <- Http1Client[F]()
          jwks   <- client.expect[JWKS](uri)
          k      <- E.delay(jwks.keys.map(jwk => (jwk.kid, convert(jwk))).toMap)
          _      <- E.delay(keys = k)
          _      <- E.delay(lastFetch = LocalDateTime.now().some)
          key    <- E.delay(keys.get(id))
        } yield key
      case _ => E.delay(keys.get(id))
    }.flatten
  }

  private def shouldFetch() =
    lastFetch.forall(_.isBefore(LocalDateTime.now().minusSeconds(minFetchDelay.toSeconds)))

  private def getKey(id: String) = E.delay {
    keys.get(id)
  }

  private def convert(jwk: JWK): SigPublicKey[A] = {
    val modulus = new BigInteger(1, Base64.getUrlDecoder.decode(jwk.n))
    val exponent = new BigInteger(1, Base64.getUrlDecoder.decode(jwk.e))
    val pubKey = KeyFactory.getInstance(jwk.kty).generatePublic(new RSAPublicKeySpec(modulus, exponent))
    SigPublicKey[A](pubKey)
  }

}

class JWKSAuthenticator[F[_] : Effect, I: Decoder, V, A: JCASigTag](expiryDuration: FiniteDuration,
                                                                    maxIdleDuration: Option[FiniteDuration],
                                                                    identityStore: IdentityStore[F, I, V],
                                                                    jwksUri: Uri,
                                                                    minFetchDelay: FiniteDuration)
                                                                   (implicit cv: JWSSigCV[F, A]) extends Authenticator[F, I, V, AugmentedJWKS[A, I]] {

  private val keyRegistry = new KeyRegistry[F, A](jwksUri, minFetchDelay)

  override def expiry: FiniteDuration = expiryDuration

  override def maxIdle: Option[FiniteDuration] = None

  /** Attempt to retrieve the raw representation of an A
    * This is primarily useful when attempting to combine AuthenticatorService,
    * to be able to evaluate an endpoint with more than one token type.
    * or simply just to prod whether the request is malformed.
    *
    * @return
    */
  override def extractRawOption(request: Request[F]): Option[String] =
    request.headers.get(Authorization).flatMap { t =>
      t.credentials match {
        case Credentials.Token(scheme, token) if scheme == AuthScheme.Bearer =>
          Some(token)
        case _ => None
      }
    }

  /** Parse the raw representation from `extractRawOption`
    *
    */
  override def parseRaw(raw: String, request: Request[F]): OptionT[F, SecuredRequest[F, V, AugmentedJWKS[A, I]]] =
    OptionT(
      (for {
        now          <- Sync[F].delay(Instant.now())
        extractedRaw <- cv.extractRaw(raw)
        publicKey    <- keyRegistry.getPublicKey(extractedRaw.header.kid.get)
        extracted    <- cv.verify(raw, publicKey.get, now)
        jwtid        <- cataOption(extracted.body.subject)
        id           <- cataOption(extracted.body.subject.flatMap(s => decode[I](s""""$s"""").toOption))
        expiry       <- cataOption(extracted.body.expiration)
        augmented = AugmentedJWKS(
          SecureRandomId.coerce(jwtid),
          extracted,
          id,
          expiry,
          None
        )
        identity <- identityStore.get(id).orAuthFailure
      } yield SecuredRequest(request, identity, augmented).some)
        .handleError(_ => None)
    )

  /** Create an authenticator from an identifier.
    *
    * @param body
    * @return
    */
  override def create(body: I): F[AugmentedJWKS[A, I]] =
    Sync[F].raiseError(new Exception("A JWKSAuthenticator cannot create an authenticator as it has no access to the private key"))

  /** Update the altered authenticator
    *
    * @param authenticator
    * @return
    */
  override def update(authenticator: AugmentedJWKS[A, I]): F[AugmentedJWKS[A, I]] = authenticator.pure[F]

  /** Delete an authenticator from a backing store, or invalidate it.
    *
    * @param authenticator
    * @return
    */
  override def discard(authenticator: AugmentedJWKS[A, I]): F[AugmentedJWKS[A, I]] = authenticator.pure[F]

  /** Renew an authenticator: Reset it's expiry and whatnot.
    *
    * @param authenticator
    * @return
    */
  override def renew(authenticator: AugmentedJWKS[A, I]): F[AugmentedJWKS[A, I]] = authenticator.pure[F]

  /** Refresh an authenticator: Primarily used for sliding window expiration
    *
    * @param authenticator
    * @return
    */
  override def refresh(authenticator: AugmentedJWKS[A, I]): F[AugmentedJWKS[A, I]] = authenticator.pure[F]

  /** Embed an authenticator directly into a response.
    * Particularly useful for adding an authenticator into unauthenticated actions
    *
    * @param response
    * @return
    */
  override def embed(response: Response[F], authenticator: AugmentedJWKS[A, I]): Response[F] = response

  /** Handles the embedding of the authenticator (if necessary) in the response,
    * and any other actions that should happen after a request related to authenticators
    *
    * @param response
    * @param authenticator
    * @return
    */
  override def afterBlock(response: Response[F], authenticator: AugmentedJWKS[A, I]): OptionT[F, Response[F]] =
    OptionT.pure[F](embed(response, authenticator))

}
