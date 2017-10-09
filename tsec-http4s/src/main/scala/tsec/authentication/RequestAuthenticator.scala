package tsec.authentication

import cats.Monad
import cats.data.{Kleisli, OptionT}
import org.http4s._
import org.http4s.dsl._

abstract class RequestAuthenticator[F[_]: Monad, Alg, I, V, Auth[_]](
    authenticator: AuthenticatorEV[F, Alg, I, V, Auth]
) extends Http4sDsl[F] {

  private val cachedKleisli: Kleisli[OptionT[F, ?], Request[F], SecuredRequest[F, Auth[Alg], V]] =
    Kleisli(authenticator.extractAndValidate)

  def apply(pf: PartialFunction[SecuredRequest[F, Auth[Alg], V], F[Response[F]]]): HttpService[F] = {
    val middleware = TSecMiddleware(cachedKleisli)
    middleware(TSecAuthService(pf))
  }

}