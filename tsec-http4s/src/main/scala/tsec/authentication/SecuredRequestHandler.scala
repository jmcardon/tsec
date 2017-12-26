package tsec.authentication

import cats.MonadError
import cats.data.Kleisli
import org.http4s._
import cats.syntax.all._
import tsec.authorization._

sealed abstract class SecuredRequestHandler[F[_], Identity, User, Auth](
    val authenticator: AuthenticatorService[F, Identity, User, Auth]
)(implicit F: MonadError[F, Throwable]) {

  /**Our default middleware **/
  private[tsec] val defaultMiddleware = TSecMiddleware(Kleisli(authenticator.extractAndValidate))

  /** Create an Authorized middleware from an Authorization **/
  private[tsec] def authorizedMiddleware(authorization: Authorization[F, User, Auth]): TSecMiddleware[F, User, Auth] = {
    val authed = Kleisli(authenticator.extractAndValidate)
      .andThen(e => authorization.isAuthorized(e))
    TSecMiddleware(authed)
  }

  /** Compose Requests **/
  def apply(pf: PartialFunction[SecuredRequest[F, User, Auth], F[Response[F]]]): HttpService[F]

  /** Lift an Authenticated Service into an HttpService **/
  def liftService(service: TSecAuthService[Auth, User, F]): HttpService[F] =
    defaultMiddleware(service)
      .handleError(_ => Response[F](Status.Unauthorized))

  /** Create an Authorized Service **/
  def authorized(authorization: Authorization[F, User, Auth])(
      pf: PartialFunction[SecuredRequest[F, User, Auth], F[Response[F]]]
  ): HttpService[F]

  /** Create an Authorized service from a TSecAuthService **/
  def liftService(
      authorization: Authorization[F, User, Auth],
      service: TSecAuthService[Auth, User, F]
  ): HttpService[F] =
    authorizedMiddleware(authorization)(service)
      .handleError(_ => Response[F](Status.Unauthorized))

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

  /** Default Construction **/
  private[tsec] def default[F[_], Identity, User, Auth](
      authenticator: AuthenticatorService[F, Identity, User, Auth]
  )(implicit F: MonadError[F, Throwable]): SecuredRequestHandler[F, Identity, User, Auth] =
    new SecuredRequestHandler[F, Identity, User, Auth](authenticator) {
      def apply(pf: PartialFunction[SecuredRequest[F, User, Auth], F[Response[F]]]): HttpService[F] =
        defaultMiddleware(TSecAuthService(pf, authenticator.afterBlock))
          .handleError(_ => Response[F](Status.Unauthorized))

      def authorized(
          authorization: Authorization[F, User, Auth]
      )(pf: PartialFunction[SecuredRequest[F, User, Auth], F[Response[F]]]): HttpService[F] =
        authorizedMiddleware(authorization)(TSecAuthService(pf, authenticator.afterBlock))
          .handleError(_ => Response[F](Status.Unauthorized))
    }

  /** Sliding/Rolling Window expiry Construction **/
  private[tsec] def rollingWindow[F[_], Identity, User, Auth](
      authenticator: AuthenticatorService[F, Identity, User, Auth]
  )(implicit F: MonadError[F, Throwable]): SecuredRequestHandler[F, Identity, User, Auth] =
    new SecuredRequestHandler[F, Identity, User, Auth](authenticator) {
      def apply(pf: PartialFunction[SecuredRequest[F, User, Auth], F[Response[F]]]): HttpService[F] =
        defaultMiddleware(TSecAuthService(pf))
          .handleError(_ => Response[F](Status.Unauthorized))

      def authorized(authorization: Authorization[F, User, Auth])(
          pf: PartialFunction[SecuredRequest[F, User, Auth], F[Response[F]]]
      ): HttpService[F] =
        authorizedMiddleware(authorization)(TSecAuthService(pf))
          .handleError(_ => Response[F](Status.Unauthorized))
    }

}
