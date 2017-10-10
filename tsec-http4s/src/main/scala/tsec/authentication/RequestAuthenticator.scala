package tsec.authentication

import cats.Monad
import cats.data.{Kleisli, OptionT}
import org.http4s._
import org.http4s.dsl._
import cats.syntax.all._
case class RequestAuthenticator[F[_]: Monad, Alg, Identity, User, Auth[_]](
    authenticator: AuthenticatorEV[F, Alg, Identity, User, Auth]
) extends Http4sDsl[F] {

  private val cachedKleisli: Kleisli[OptionT[F, ?], Request[F], SecuredRequest[F, Auth[Alg], User]] =
    Kleisli(authenticator.extractAndValidate)

  def apply(pf: PartialFunction[SecuredRequest[F, Auth[Alg], User], F[Response[F]]]): HttpService[F] = {
    val middleware = TSecMiddleware(cachedKleisli)
    middleware(TSecAuthService(pf))
  }

  def withRollingWindow(pf: PartialFunction[SecuredRequest[F, Auth[Alg], User], F[Response[F]]]): HttpService[F] = {
    val middleware = TSecMiddleware(cachedKleisli)
    middleware(TSecAuthService(pf, authenticator.afterBlock))
  }

}