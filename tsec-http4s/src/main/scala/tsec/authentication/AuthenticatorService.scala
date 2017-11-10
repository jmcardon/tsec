package tsec.authentication

import cats.data.OptionT
import org.http4s.{Request, Response}

import scala.concurrent.duration.FiniteDuration

/** A base typeclass for generating authenticators, i.e cookies, tokens, JWTs etc.
  *
  * @tparam I The Identifier type
  * @tparam V The value type, i.e user, or possibly only partial information
  * @tparam Authenticator the type of authenticator
  */
trait AuthenticatorService[F[_], I, V, Authenticator] {
  val expiry: FiniteDuration
  val maxIdle: Option[FiniteDuration]

  /** Attempt to retrieve the raw representation of an Authenticator
    * This is primarily useful when attempting to combine AuthenticatorService,
    * to be able to evaluate an endpoint with more than one token type.
    * or simply just to prod whether the request is malformed.
    *
    * @return
    */
  def tryExtractRaw(request: Request[F]): Option[String]

  /** Return a secured request from a request, that carries our authenticator
    * @param request
    * @return
    */
  def extractAndValidate(request: Request[F]): OptionT[F, SecuredRequest[F, V, Authenticator]]

  /** Create an authenticator from an identifier.
    * @param body
    * @return
    */
  def create(body: I): OptionT[F, Authenticator]

  /** Update the altered authenticator
    *
    * @param authenticator
    * @return
    */
  def update(authenticator: Authenticator): OptionT[F, Authenticator]

  /** Delete an authenticator from a backing store, or invalidate it.
    *
    * @param authenticator
    * @return
    */
  def discard(authenticator: Authenticator): OptionT[F, Authenticator]

  /** Renew an authenticator: Reset it's expiry and whatnot.
    *
    * @param authenticator
    * @return
    */
  def renew(authenticator: Authenticator): OptionT[F, Authenticator]

  /** Refresh an authenticator: Primarily used for sliding window expiration
    *
    * @param authenticator
    * @return
    */
  def refresh(authenticator: Authenticator): OptionT[F, Authenticator]

  /** Embed an authenticator directly into a response.
    * Particularly useful for adding an authenticator into unauthenticated actions
    *
    * @param response
    * @return
    */
  def embed(response: Response[F], authenticator: Authenticator): Response[F]

  /** Handles the embedding of the authenticator (if necessary) in the response,
    * and any other actions that should happen after a request related to authenticators
    *
    * @param response
    * @param authenticator
    * @return
    */
  def afterBlock(response: Response[F], authenticator: Authenticator): OptionT[F, Response[F]]

}
