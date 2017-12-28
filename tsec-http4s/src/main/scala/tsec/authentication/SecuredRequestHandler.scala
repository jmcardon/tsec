package tsec.authentication

import cats.MonadError
import cats.data.{Kleisli, OptionT}
import org.http4s._
import cats.syntax.all._
import tsec.authorization._

sealed abstract class SecuredRequestHandler[F[_], Identity, User, Auth](
    val authenticator: AuthenticatorService[F, Identity, User, Auth]
)(implicit F: MonadError[F, Throwable]) {

  private[tsec] val catchAllFailures: Throwable => F[Response[F]] = _ => F.pure(Response[F](Status.Unauthorized))

  private[tsec] val defaultNotAuthorized: F[Response[F]] = F.pure(Response[F](Status.Unauthorized))

  /** Create an Authorized middleware from an Authorization **/
  private[tsec] def authorizedMiddleware(
      authorization: Authorization[F, User, Auth],
      onNotAuthorized: F[Response[F]]
  ): TSecMiddleware[F, User, Auth] = {
    val authed = Kleisli(authenticator.extractAndValidate)
      .andThen(e => authorization.isAuthorized(e))
    TSecMiddleware(authed, onNotAuthorized)
  }

  /** Compose Requests **/
  def apply(
      pf: PartialFunction[SecuredRequest[F, User, Auth], F[Response[F]]],
      onNotAuthorized: F[Response[F]] = defaultNotAuthorized
  ): HttpService[F]

  /** Lift an Authenticated Service into an HttpService **/
  def liftService(
      service: TSecAuthService[Auth, User, F],
      onNotAuthorized: F[Response[F]] = defaultNotAuthorized
  ): HttpService[F] = {
    val middleware = TSecMiddleware(Kleisli(authenticator.extractAndValidate), onNotAuthorized)

    middleware(service)
      .handleErrorWith(e => Kleisli.lift(OptionT.liftF(catchAllFailures(e))))
  }

  /** Create an Authorized Service **/
  def authorized(authorization: Authorization[F, User, Auth])(
      pf: PartialFunction[SecuredRequest[F, User, Auth], F[Response[F]]],
      onNotAuthorized: F[Response[F]] = defaultNotAuthorized
  ): HttpService[F]

  /** Create an Authorized service from a TSecAuthService **/
  def liftAuthorizedService(
      authorization: Authorization[F, User, Auth],
      service: TSecAuthService[Auth, User, F],
      onNotAuthorized: F[Response[F]] = defaultNotAuthorized
  ): HttpService[F] =
    authorizedMiddleware(authorization, onNotAuthorized)(service)
      .handleErrorWith(e => Kleisli.lift(OptionT.liftF(catchAllFailures(e))))

}

object SecuredRequestHandler {

  /** Build our SecuredRequestHandler detecting whether it is rolling window or not **/
  def apply[F[_], Identity, User, Auth](
      authenticator: AuthenticatorService[F, Identity, User, Auth]
  )(implicit F: MonadError[F, Throwable]): SecuredRequestHandler[F, Identity, User, Auth] =
    if (authenticator.maxIdle.isDefined) {
      rollingWindow[F, Identity, User, Auth](authenticator)
    } else {
      default[F, Identity, User, Auth](authenticator)
    }


  /** Sliding/Rolling Window expiry Construction **/
  private[tsec] def rollingWindow[F[_], Identity, User, Auth](
      authenticator: AuthenticatorService[F, Identity, User, Auth]
  )(implicit F: MonadError[F, Throwable]): SecuredRequestHandler[F, Identity, User, Auth] =
    new SecuredRequestHandler[F, Identity, User, Auth](authenticator) {

      /** Compose Requests **/
      def apply(
          pf: PartialFunction[SecuredRequest[F, User, Auth], F[Response[F]]],
          onNotAuthorized: F[Response[F]] = defaultNotAuthorized
      ): HttpService[F] = {
        val middleware = TSecMiddleware(Kleisli(authenticator.extractAndValidate), onNotAuthorized)
        middleware(TSecAuthService(pf, authenticator.afterBlock))
          .handleErrorWith(e => Kleisli.lift(OptionT.liftF(catchAllFailures(e))))
      }

      /** Create an Authorized Service **/
      def authorized(authorization: Authorization[F, User, Auth])(
          pf: PartialFunction[SecuredRequest[F, User, Auth], F[Response[F]]],
          onNotAuthorized: F[Response[F]] = defaultNotAuthorized
      ): HttpService[F] =
        authorizedMiddleware(authorization, onNotAuthorized)(TSecAuthService(pf, authenticator.afterBlock))
          .handleErrorWith(e => Kleisli.lift(OptionT.liftF(catchAllFailures(e))))

    }
  
  /** Default Construction **/
  private[tsec] def default[F[_], Identity, User, Auth](
      authenticator: AuthenticatorService[F, Identity, User, Auth]
  )(implicit F: MonadError[F, Throwable]): SecuredRequestHandler[F, Identity, User, Auth] =
    new SecuredRequestHandler[F, Identity, User, Auth](authenticator) {

      /** Compose Requests **/
      def apply(
          pf: PartialFunction[SecuredRequest[F, User, Auth], F[Response[F]]],
          onNotAuthorized: F[Response[F]] = defaultNotAuthorized
      ): HttpService[F] = {
        val middleware = TSecMiddleware(Kleisli(authenticator.extractAndValidate), onNotAuthorized)

        middleware(TSecAuthService(pf))
          .handleErrorWith(e => Kleisli.lift(OptionT.liftF(catchAllFailures(e))))

      }

      /** Create an Authorized Service **/
      def authorized(authorization: Authorization[F, User, Auth])(
          pf: PartialFunction[SecuredRequest[F, User, Auth], F[Response[F]]],
          onNotAuthorized: F[Response[F]] = defaultNotAuthorized
      ): HttpService[F] =
        authorizedMiddleware(authorization, onNotAuthorized)(TSecAuthService(pf))
          .handleErrorWith(e => Kleisli.lift(OptionT.liftF(catchAllFailures(e))))

    }

}
