package tsec.auth

import cats.Monad
import cats.data.{Kleisli, OptionT}
import org.http4s._
import org.http4s.server._
import org.http4s.dsl._

abstract class RequestAuthenticator[F[_]: Monad, Alg, I, V](
    authenticator: Authenticator[F, Alg, I, V],
    extract: Request[F] => String
) extends Http4sDsl[F] {

  def apply(pf: PartialFunction[AuthedRequest[F, V], F[Response[F]]]): HttpService[F] =
    authedRequest(AuthedService(pf))

  private lazy val authedRequest: AuthMiddleware[F, V] =
    _.compose(
      (req: Request[F]) =>
        for {
          stringRepr <- OptionT.pure[F](extract(req))
          v          <- authenticator.retrieveIdentity(stringRepr)
        } yield AuthedRequest(v, req)
    )
}
