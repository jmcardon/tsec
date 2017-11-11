package tsec.authentication

import cats.Applicative
import cats.data.{Kleisli, NonEmptyList, OptionT}
import cats.effect.Sync
import org.http4s.{HttpService, Request, Response, Status}

import scala.annotation.tailrec
import scala.concurrent.duration.FiniteDuration

/** A base typeclass for generating authenticators, i.e cookies, tokens, JWTs etc.
  *
  * @tparam I The Identifier type
  * @tparam V The value type, i.e user, or possibly only partial information
  * @tparam Authenticator the type of authenticator
  */
abstract class AuthenticatorService[F[_]: Sync, I, V, Authenticator] {
  val expiry: FiniteDuration
  val maxIdle: Option[FiniteDuration]

  /** Attempt to retrieve the raw representation of an Authenticator
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
  def parseRaw(raw: String, request: Request[F]): OptionT[F, SecuredRequest[F, V, Authenticator]]

  /** Return a secured request from a request, that carries our authenticator
    * @param request
    * @return
    */
  def extractAndValidate(request: Request[F]): OptionT[F, SecuredRequest[F, V, Authenticator]] =
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

object AuthenticatorService {

  final class AuthServiceSyntax[F[_], I, V, A](val auth: AuthenticatorService[F, I, V, A]) extends AnyVal {
    def composeExtract[B <: Authenticator[I]](
        other: AuthenticatorService[F, I, V, B]
    )(implicit ev: A <:< Authenticator[I]): AuthExtractorService[F, V, Authenticator[I]] =
      Kleisli { r: Request[F] =>
        auth.extractRawOption(r) match {
          case Some(_) =>
            auth
              .extractAndValidate(r)
              .asInstanceOf[OptionT[F, SecuredRequest[F, V, Authenticator[I]]]] //we need to do this :(
          case None =>
            other
              .extractAndValidate(r)
              .asInstanceOf[OptionT[F, SecuredRequest[F, V, Authenticator[I]]]]
        }
      }

    def foldAuthenticate(others: AuthenticatorService[F, I, V, _ <: Authenticator[I]]*)(
        service: TSecAuthService[F, V, Authenticator[I]]
    )(implicit F: Sync[F]): HttpService[F] =
      Kleisli { request: Request[F] =>
        auth.extractRawOption(request) match {
          case Some(raw) =>
            val coerced = auth.asInstanceOf[AuthenticatorService[F, I, V, Authenticator[I]]]
            coerced
              .parseRaw(raw, request)
              .asInstanceOf[OptionT[F, SecuredRequest[F, V, Authenticator[I]]]]
              .flatMap(r => service.andThen(coerced.afterBlock(_, r.authenticator)).run(r))
          case None =>
            tailRecAuth(service, request, others.toList)
        }
      }
  }

  /** Apply a fold on AuthenticatorServices, which rejects the request if none pass **/
  @tailrec
  def tailRecAuth[F[_], I, V, A](
      service: TSecAuthService[F, V, Authenticator[I]],
      request: Request[F],
      tail: List[AuthenticatorService[F, I, V, _ <: Authenticator[I]]]
  )(implicit F: Sync[F]): OptionT[F, Response[F]] =
    tail match {
      case Nil => OptionT.pure[F](Response[F](Status.Unauthorized))
      case x :: xs =>
        x.extractRawOption(request) match {
          case Some(raw) =>
            val coerced = x.asInstanceOf[AuthenticatorService[F, I, V, Authenticator[I]]]
            coerced
              .parseRaw(raw, request)
              .asInstanceOf[OptionT[F, SecuredRequest[F, V, Authenticator[I]]]]
              .flatMap(r => service.andThen(coerced.afterBlock(_, r.authenticator)).run(r))
          case None =>
            tailRecAuth(service, request, xs)
        }
    }

  implicit def authenticatorServiceSyntax[F[_], I, V, A](
      auth: AuthenticatorService[F, I, V, A]
  ): AuthServiceSyntax[F, I, V, A] =
    new AuthServiceSyntax[F, I, V, A](auth)

  def foldAuthenticate[F[_], I, V, A](others: AuthenticatorService[F, I, V, _ <: Authenticator[I]]*)(
      service: TSecAuthService[F, V, Authenticator[I]]
  )(implicit F: Sync[F]): HttpService[F] =
    Kleisli { request: Request[F] =>
      tailRecAuth(service, request, others.toList)
    }

}
