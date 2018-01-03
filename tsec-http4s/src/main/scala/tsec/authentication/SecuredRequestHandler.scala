package tsec.authentication

import cats.MonadError
import cats.data.{Kleisli, OptionT}
import org.http4s._
import cats.syntax.all._
import tsec.authorization._
import org.log4s._

sealed abstract class SecuredRequestHandler[F[_], Identity, User, Auth](
    val authenticator: AuthenticatorService[F, Identity, User, Auth]
)(implicit F: MonadError[F, Throwable]) {

  private[tsec] val cachedUnauthorized: Response[F]                       = Response[F](Status.Unauthorized)
  private[tsec] val defaultNotAuthenticated: Request[F] => F[Response[F]] = _ => F.pure(cachedUnauthorized)

  /** Create an Authorized middleware from an Authorization **/
  private[tsec] def authorizedMiddleware(
      authorization: Authorization[F, User, Auth],
      onNotAuthenticated: Request[F] => F[Response[F]]
  ): TSecMiddleware[F, User, Auth] = {
    val authed = Kleisli(authenticator.extractAndValidate)
      .andThen(e => authorization.isAuthorized(e))
    TSecMiddleware(authed, onNotAuthenticated)
  }

  /** Compose Requests **/
  def apply(
      pf: PartialFunction[SecuredRequest[F, User, Auth], F[Response[F]]],
      onNotAuthenticated: Request[F] => F[Response[F]] = defaultNotAuthenticated
  ): HttpService[F]

  /** Lift an Authenticated Service into an HttpService **/
  def liftService(
      service: TSecAuthService[User, Auth, F],
      onNotAuthenticated: Request[F] => F[Response[F]] = defaultNotAuthenticated
  ): HttpService[F] = {
    val middleware = TSecMiddleware(Kleisli(authenticator.extractAndValidate), onNotAuthenticated)

    middleware(service)
      .handleErrorWith { e =>
        SecuredRequestHandler.logger.error(e)("Caught unhandled exception in authenticated service")
        Kleisli.liftF(OptionT.pure(cachedUnauthorized))
      }
  }

  /** Create an Authorized Service **/
  def authorized(authorization: Authorization[F, User, Auth])(
      pf: PartialFunction[SecuredRequest[F, User, Auth], F[Response[F]]],
      onNotAuthenticated: Request[F] => F[Response[F]] = defaultNotAuthenticated
  ): HttpService[F]

  /** Create an Authorized service from a TSecAuthService **/
  def liftAuthorizedService(
      authorization: Authorization[F, User, Auth],
      service: TSecAuthService[User, Auth, F],
      onNotAuthenticated: Request[F] => F[Response[F]] = defaultNotAuthenticated
  ): HttpService[F] =
    authorizedMiddleware(authorization, onNotAuthenticated)(service)
      .handleErrorWith { e =>
        SecuredRequestHandler.logger.error(e)("Caught unhandled exception in authenticated service")
        Kleisli.liftF(OptionT.pure(cachedUnauthorized))
      }

}

object SecuredRequestHandler {
  private[authentication] val logger = getLogger("tsec.authentication.SecureRequestHandler")

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
          onNotAuthenticated: Request[F] => F[Response[F]] = defaultNotAuthenticated
      ): HttpService[F] = {
        val middleware = TSecMiddleware(Kleisli(authenticator.extractAndValidate), onNotAuthenticated)
        middleware(TSecAuthService(pf, authenticator.afterBlock))
          .handleErrorWith { e =>
            logger.error(e)("Caught unhandled exception in authenticated service")
            Kleisli.liftF(OptionT.pure(cachedUnauthorized))
          }
      }

      /** Create an Authorized Service **/
      def authorized(authorization: Authorization[F, User, Auth])(
          pf: PartialFunction[SecuredRequest[F, User, Auth], F[Response[F]]],
          onNotAuthenticated: Request[F] => F[Response[F]] = defaultNotAuthenticated
      ): HttpService[F] =
        authorizedMiddleware(authorization, onNotAuthenticated)(TSecAuthService(pf, authenticator.afterBlock))
          .handleErrorWith { e =>
            logger.error(e)("Caught unhandled exception in authenticated service")
            Kleisli.liftF(OptionT.pure(cachedUnauthorized))
          }

    }

  /** Default Construction **/
  private[tsec] def default[F[_], Identity, User, Auth](
      authenticator: AuthenticatorService[F, Identity, User, Auth]
  )(implicit F: MonadError[F, Throwable]): SecuredRequestHandler[F, Identity, User, Auth] =
    new SecuredRequestHandler[F, Identity, User, Auth](authenticator) {

      /** Compose Requests **/
      def apply(
          pf: PartialFunction[SecuredRequest[F, User, Auth], F[Response[F]]],
          onNotAuthenticated: Request[F] => F[Response[F]] = defaultNotAuthenticated
      ): HttpService[F] = {
        val middleware = TSecMiddleware(Kleisli(authenticator.extractAndValidate), onNotAuthenticated)

        middleware(TSecAuthService(pf))
          .handleErrorWith { e =>
            logger.error(e)("Caught unhandled exception in authenticated service")
            Kleisli.liftF(OptionT.pure(cachedUnauthorized))
          }

      }

      /** Create an Authorized Service **/
      def authorized(authorization: Authorization[F, User, Auth])(
          pf: PartialFunction[SecuredRequest[F, User, Auth], F[Response[F]]],
          onNotAuthenticated: Request[F] => F[Response[F]] = defaultNotAuthenticated
      ): HttpService[F] =
        authorizedMiddleware(authorization, onNotAuthenticated)(TSecAuthService(pf))
          .handleErrorWith { e =>
            logger.error(e)("Caught unhandled exception in authenticated service")
            Kleisli.liftF(OptionT.pure(cachedUnauthorized))
          }
    }

}
