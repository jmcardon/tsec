package tsec.authentication

import cats.data.OptionT
import cats.effect.Sync
import org.http4s.{Request, Response}

import scala.concurrent.duration.FiniteDuration

/** A base typeclass for generating authenticators, i.e cookies, tokens, JWTs etc.
  *
  * @tparam I The Identifier type
  * @tparam V The value type, i.e user, or possibly only partial information
  * @tparam A the type of authenticator
  */
abstract class AuthenticatorService[F[_]: Sync, I, V, A] {
  val expiry: FiniteDuration
  val maxIdle: Option[FiniteDuration]

  /** Attempt to retrieve the raw representation of an A
    * This is primarily useful when attempting to combine AuthenticatorService,
    * to be able to evaluate an endpoint with more than one token type.
    * or simply just to prod whether the request is malformed.
    *
    * @return
    */
  def extractRawOption(request: Request[F]): Option[String]

  /** Parse the raw representation from `extractRawOption`
    *
    */
  def parseRaw(raw: String, request: Request[F]): OptionT[F, SecuredRequest[F, V, A]]

  /** Return a secured request from a request, that carries our authenticator
    * @param request
    * @return
    */
  def extractAndValidate(request: Request[F]): OptionT[F, SecuredRequest[F, V, A]] =
    extractRawOption(request) match {
      case Some(raw) =>
        parseRaw(raw, request)
      case None =>
        OptionT.none
    }

  /** Create an authenticator from an identifier.
    * @param body
    * @return
    */
  def create(body: I): F[A]

  /** Update the altered authenticator
    *
    * @param authenticator
    * @return
    */
  def update(authenticator: A): F[A]

  /** Delete an authenticator from a backing store, or invalidate it.
    *
    * @param authenticator
    * @return
    */
  def discard(authenticator: A): F[A]

  /** Renew an authenticator: Reset it's expiry and whatnot.
    *
    * @param authenticator
    * @return
    */
  def renew(authenticator: A): F[A]

  /** Refresh an authenticator: Primarily used for sliding window expiration
    *
    * @param authenticator
    * @return
    */
  def refresh(authenticator: A): F[A]

  /** Embed an authenticator directly into a response.
    * Particularly useful for adding an authenticator into unauthenticated actions
    *
    * @param response
    * @return
    */
  def embed(response: Response[F], authenticator: A): Response[F]

  /** Handles the embedding of the authenticator (if necessary) in the response,
    * and any other actions that should happen after a request related to authenticators
    *
    * @param response
    * @param authenticator
    * @return
    */
  def afterBlock(response: Response[F], authenticator: A): OptionT[F, Response[F]]

}

