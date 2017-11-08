package tsec.authentication

import cats.MonadError
import cats.data.Kleisli
import org.http4s._
import cats.syntax.all._
import tsec.authorization._

sealed abstract class SecuredRequestHandler[F[_], Identity, User, Auth](
    val authenticator: Authenticator[F, Identity, User, Auth]
)(implicit F: MonadError[F, Throwable]) {

  protected def authorizedMiddleware(authorization: Authorization[F, User, Auth]): TSecMiddleware[F, User, Auth] = {
    val authed = Kleisli(authenticator.extractAndValidate)
      .andThen(e => authorization.isAuthorized(e))
    TSecMiddleware(authed)
  }

  def apply(pf: PartialFunction[SecuredRequest[F, User, Auth], F[Response[F]]]): HttpService[F]

  def authorized(authorization: Authorization[F, User, Auth])(
      pf: PartialFunction[SecuredRequest[F, User, Auth], F[Response[F]]]
  ): HttpService[F]

}

object SecuredRequestHandler {

  def apply[F[_], Identity, User, Auth](
      authenticator: Authenticator[F, Identity, User, Auth],
      rolling: Boolean = false
  )(implicit F: MonadError[F, Throwable]): SecuredRequestHandler[F, Identity, User, Auth] = {
    val middleware = TSecMiddleware(Kleisli(authenticator.extractAndValidate))
    if (rolling) {
      new SecuredRequestHandler[F, Identity, User, Auth](authenticator) {
        def apply(pf: PartialFunction[SecuredRequest[F, User, Auth], F[Response[F]]]): HttpService[F] =
          middleware(TSecAuthService(pf))
            .handleError(_ => Response[F](Status.Unauthorized))

        def authorized(authorization: Authorization[F, User, Auth])(
            pf: PartialFunction[SecuredRequest[F, User, Auth], F[Response[F]]]
        ): HttpService[F] =
          authorizedMiddleware(authorization)(TSecAuthService(pf))
            .handleError(_ => Response[F](Status.Unauthorized))
      }
    } else
      new SecuredRequestHandler[F, Identity, User, Auth](authenticator) {
        def apply(pf: PartialFunction[SecuredRequest[F, User, Auth], F[Response[F]]]): HttpService[F] =
          middleware(TSecAuthService(pf, authenticator.afterBlock))
            .handleError(_ => Response[F](Status.Unauthorized))

        def authorized(
            authorization: Authorization[F, User, Auth]
        )(pf: PartialFunction[SecuredRequest[F, User, Auth], F[Response[F]]]): HttpService[F] =
          authorizedMiddleware(authorization)(TSecAuthService(pf, authenticator.afterBlock))
            .handleError(_ => Response[F](Status.Unauthorized))
      }
  }
}
