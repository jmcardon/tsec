package tsec.authentication

import cats.Monad
import cats.data.{Kleisli, OptionT}
import org.http4s._
import org.http4s.dsl._
import cats.syntax.all._
import tsec.jws.mac.JWTMac
case class RequestAuthenticator[F[_]: Monad, Alg, Identity, User, Auth[_]](
    authenticator: AuthenticatorEV[F, Alg, Identity, User, Auth]
) {

  private val cachedKleisli: Kleisli[OptionT[F, ?], Request[F], SecuredRequest[F, Auth[Alg], User]] =
    Kleisli(authenticator.extractAndValidate)

  def apply(
      pf: PartialFunction[SecuredRequest[F, Auth[Alg], User], F[Response[F]]]
  ): HttpService[F] = {
    val middleware = TSecMiddleware(cachedKleisli)
    middleware(TSecAuthService(pf))
  }

  def withRollingWindow(
      pf: PartialFunction[SecuredRequest[F, Auth[Alg], User], F[Response[F]]]
  ): HttpService[F] = {
    val middleware = TSecMiddleware(cachedKleisli)
    middleware(TSecAuthService(pf, authenticator.afterBlock))
  }

}

object RequestAuthenticator {

  private [authentication] final class EncryptedPartial[F[_]](val dummy: Boolean = true) extends AnyVal {
    def apply[Alg, Identity, User](
        authenticator: AuthenticatorEV[F, Alg, Identity, User, AuthEncryptedCookie[?, Identity]]
    )(implicit F: Monad[F]) =
      RequestAuthenticator[F, Alg, Identity, User, AuthEncryptedCookie[?, Identity]](authenticator)
  }

  private [authentication] final class CookiePartial[F[_]](val dummy: Boolean = true) extends AnyVal {
    def apply[Alg, Identity, User](
      authenticator: AuthenticatorEV[F, Alg, Identity, User, AuthenticatedCookie[?, Identity]]
    )(implicit F: Monad[F]) =
      RequestAuthenticator[F, Alg, Identity, User, AuthenticatedCookie[?, Identity]](authenticator)
  }

  private [authentication] final class JWTPartial[F[_]](val dummy: Boolean = true) extends AnyVal {
    def apply[Alg, Identity, User](
      authenticator: AuthenticatorEV[F, Alg, Identity, User, JWTMac]
    )(implicit F: Monad[F]) =
      RequestAuthenticator[F, Alg, Identity, User, JWTMac](authenticator)
  }

  final def encryptedCookie[F[_]]: EncryptedPartial[F] = new EncryptedPartial[F]()

  final def signedCookie[F[_]]: CookiePartial[F] = new CookiePartial[F]()

  final def jwt[F[_]]: JWTPartial[F] = new JWTPartial[F]()
}
