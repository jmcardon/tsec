package tsec.authentication

import cats.data.OptionT
import tsec.cipher.symmetric.imports.AuthEncryptor
import tsec.cookies._
import tsec.jws.mac.{JWSMacCV, JWTMac}
import org.http4s.{Request, Response}

/** A base typeclass for generating authenticators, i.e cookies, tokens, JWTs etc.
  *
  * @tparam Alg The related cryptographic algorithm used in authentication
  * @tparam I The Identifier type
  * @tparam V The value type, i.e user, or possibly only partial information
  */
trait AuthenticatorEV[F[_], Alg, I, V] {
  type Authenticator[T]

  /** Return a secured request from a request, that carries our authenticator
    * @param request
    * @return
    */
  def extractAndValidate(request: Request[F]): OptionT[F, SecuredRequest[F, Authenticator[Alg], V]]

  /**
    * Create an authenticator from an identifier.
    * @param body
    * @return
    */
  def create(body: I): OptionT[F, Authenticator[Alg]]

  /**
    * Renew an authenticator: Reset it's expiry and whatnot.
    * @param authenticator
    * @return
    */
  def renew(authenticator: Authenticator[Alg]): OptionT[F, Authenticator[Alg]]

  /** Refresh an authenticator: Primarily used for sliding window expiration
    *
    * @param authenticator
    * @return
    */
  def refresh(authenticator: Authenticator[Alg]): OptionT[F, Authenticator[Alg]]

  /** Embed an authenticator directly into a response.
    * Particularly useful for adding an authenticator into unauthenticated actions
    *
    * @param response
    * @return
    */
  def embed(response: Response[F], authenticator: Authenticator[Alg]): Response[F]

  /** Handles the embedding of the authenticator (if necessary) in the response,
    * and any other actions that should happen after a request related to authenticators
    *
    * @param response
    * @param authenticator
    * @return
    */
  def afterBlock(response: Response[F], authenticator: Authenticator[Alg]): OptionT[F, Response[F]]

}

object AuthenticatorEV {
  type AuthAux[F[_], A, I, V, T[_]] = AuthenticatorEV[F, A, I, V] {
    type Authenticator[B] = T[B]
  }
}

abstract class JWTMacAuthenticator[F[_], A, I, V](implicit jWSMacCV: JWSMacCV[F, A])
    extends AuthenticatorEV[F, A, I, V] {
  type Authenticator[T] = JWTMac[T]

}
