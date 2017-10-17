package tsec.authentication

import cats.{Monad, MonadError}
import cats.data.{Kleisli, OptionT}
import org.http4s._
import cats.syntax.all._
import tsec.jws.mac.JWTMac
import tsec.authorization._

sealed abstract class RequestHandler[F[_], Alg, Identity, User, Auth[_]](
    val authenticator: Authenticator[F, Alg, Identity, User, Auth]
)(implicit F: MonadError[F, Throwable]) {
  private val defaultMiddleware: TSecMiddleware[F, Auth[Alg], User] = TSecMiddleware(
    Kleisli(authenticator.extractAndValidate)
  )

  protected def authorizedMiddleware(authorization: Authorization[F, User]): TSecMiddleware[F, Auth[Alg], User] = {
    val authed = Kleisli(authenticator.extractAndValidate)
      .andThen(e => authorization.isAuthorized(e))
    TSecMiddleware(authed)
  }

  def apply(pf: PartialFunction[SecuredRequest[F, Auth[Alg], User], F[Response[F]]]): HttpService[F]

  def authorized(authorization: Authorization[F, User])(
      pf: PartialFunction[SecuredRequest[F, Auth[Alg], User], F[Response[F]]]
  ): HttpService[F]

}

object RequestHandler {

  def apply[F[_], Alg, Identity, User, Auth[_]](
      authenticator: Authenticator[F, Alg, Identity, User, Auth],
      rolling: Boolean = false
  )(implicit F: MonadError[F, Throwable]): RequestHandler[F, Alg, Identity, User, Auth] = {
    val middleware = TSecMiddleware(Kleisli(authenticator.extractAndValidate))
    if (rolling) {
      new RequestHandler[F, Alg, Identity, User, Auth](authenticator) {
        def apply(pf: PartialFunction[SecuredRequest[F, Auth[Alg], User], F[Response[F]]]): HttpService[F] =
          middleware(TSecAuthService(pf))
            .handleError(_ => Response[F](Status.Forbidden))

        def authorized(authorization: Authorization[F, User])(
            pf: PartialFunction[SecuredRequest[F, Auth[Alg], User], F[Response[F]]]
        ): HttpService[F] =
          authorizedMiddleware(authorization)(TSecAuthService(pf))
            .handleError(_ => Response[F](Status.Forbidden))
      }
    } else
      new RequestHandler[F, Alg, Identity, User, Auth](authenticator) {
        def apply(pf: PartialFunction[SecuredRequest[F, Auth[Alg], User], F[Response[F]]]): HttpService[F] =
          middleware(TSecAuthService(pf, authenticator.afterBlock))
            .handleError(_ => Response[F](Status.Forbidden))

        def authorized(
            authorization: Authorization[F, User]
        )(pf: PartialFunction[SecuredRequest[F, Auth[Alg], User], F[Response[F]]]): HttpService[F] =
          authorizedMiddleware(authorization)(TSecAuthService(pf, authenticator.afterBlock))
            .handleError(_ => Response[F](Status.Forbidden))
      }
  }

  private[authentication] final class DefaultEncrypted[F[_]](val dummy: Boolean = true) extends AnyVal {
    def apply[Alg, Identity, User](
        authenticator: Authenticator[F, Alg, Identity, User, AuthEncryptedCookie[?, Identity]],
        rolling: Boolean = false
    )(implicit F: MonadError[F, Throwable]) =
      RequestHandler[F, Alg, Identity, User, AuthEncryptedCookie[?, Identity]](authenticator, rolling)
  }

  private[authentication] final class DefaultCookie[F[_]](val dummy: Boolean = true) extends AnyVal {
    def apply[Alg, Identity, User](
        authenticator: Authenticator[F, Alg, Identity, User, AuthenticatedCookie[?, Identity]],
        rolling: Boolean = false
    )(implicit F: MonadError[F, Throwable]) =
      RequestHandler[F, Alg, Identity, User, AuthenticatedCookie[?, Identity]](authenticator, rolling)
  }

  private[authentication] final class DefaultJWT[F[_]](val dummy: Boolean = true) extends AnyVal {
    def apply[Alg, Identity, User](
        authenticator: Authenticator[F, Alg, Identity, User, JWTMac],
        rolling: Boolean = false
    )(implicit F: MonadError[F, Throwable]) =
      RequestHandler[F, Alg, Identity, User, JWTMac](authenticator, rolling)
  }

  final def encryptedCookie[F[_]]: DefaultEncrypted[F] = new DefaultEncrypted[F]()

  final def signedCookie[F[_]]: DefaultCookie[F] = new DefaultCookie[F]()

  final def jwt[F[_]]: DefaultJWT[F] = new DefaultJWT[F]()

}
