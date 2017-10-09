package tsec.auth

import cats.Monad
import cats.data.{Kleisli, OptionT}
import org.http4s._
import org.http4s.server._
import org.http4s.dsl._

abstract class RequestAuthenticator[F[_]: Monad, Alg, I, V](
    authenticator: AuthenticatorEV[F, Alg, I, V]
) extends Http4sDsl[F] {
  import authenticator.Authenticator

  def apply(pf: PartialFunction[SecuredRequest[F, Authenticator[Alg], V], F[Response[F]]]): HttpService[F] = {
    val middleware = TSecMiddleware(extractedKleisli)
    middleware(TSecAuthService(pf))
  }

  private val extractedKleisli =
    Kleisli[OptionT[F, ?], Request[F], SecuredRequest[F, Authenticator[Alg], V]](
      req => authenticator.extractAndValidate(req)
    )

}
