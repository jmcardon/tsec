package tsec.authentication

import cats.data.OptionT
import tsec.cipher.symmetric.imports.AuthEncryptor
import tsec.cookies._
import tsec.jws.mac.{JWSMacCV, JWTMac}
import org.http4s.{Request, Response}

/** A base typeclass for generating authenticators, i.e cookies, tokens, JWTs etc.
  *
  * @tparam I The Identifier type
  * @tparam V The value type, i.e user, or possibly only partial information
  * @tparam Authenticator the type of authenticator
  */
trait Authenticator[F[_], I, V, Authenticator] {

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
