package tsec

import cats.{Applicative, Monad}
import cats.arrow.Choice
import cats.data.{Kleisli, OptionT}
import org.http4s.{Request, Response}
import org.http4s.server.Middleware

package object auth{

  trait BackingStore[F[_], I, V] {
    def put(elem: V):  F[Int]

    def get(id: I): OptionT[F, V]

    def update(v: V): F[Int]

    def delete(id: I): F[Int]
  }

  /** Inspired from the Silhouette `SecuredRequest`
    *
    */
  final case class SecuredRequest[F[_], Auth, Identity](request: Request[F], authenticator: Auth, identity: Identity)

  type TSecMiddleware[F[_], A, I] = Middleware[OptionT[F, ?], SecuredRequest[F, A, I], Response[F], Request[F], Response[F]]

  object TSecMiddleware {
    def apply[F[_]: Monad, A, I](authedStuff: Kleisli[OptionT[F, ?], Request[F], SecuredRequest[F, A, I]]): TSecMiddleware[F, A, I] =
      service => {
        service.compose(authedStuff)
      }
    //Todo: Deal with the Explicit error
//
//    def apply[F[_], Err, T](
//      authUser: Kleisli[F, Request[F], Either[Err, T]],
//      onFailure: Kleisli[OptionT[F, ?], AuthedRequest[F, Err], Response[F]]
//    )(implicit F: Monad[F], C: Choice[Kleisli[OptionT[F, ?], ?, ?]]): AuthMiddleware[F, T] = {
//      service: AuthedService[F, T] =>
//        C.choice(onFailure, service)
//          .local { authed: AuthedRequest[F, Either[Err, T]] =>
//            authed.authInfo.bimap(
//              err => AuthedRequest(err, authed.req),
//              suc => AuthedRequest(suc, authed.req)
//            )
//          }
//          .compose(AuthedRequest(authUser.run).mapF(OptionT.liftF(_)))
//    }
  }


  type TSecAuthService[F[_], A, I] = Kleisli[OptionT[F, ?], SecuredRequest[F, A, I], Response[F]]

  object TSecAuthService {
    /** Lifts a partial function to an `AuthedService`.  Responds with
      * [[org.http4s.Response.notFoundFor]], which generates a 404, for any request
      * where `pf` is not defined.
      */
    def apply[F[_], A, I](pf: PartialFunction[SecuredRequest[F, A, I], F[Response[F]]])(
      implicit F: Applicative[F]): TSecAuthService[F, A, I] =
      Kleisli(req => pf.andThen(OptionT.liftF(_)).applyOrElse(req, Function.const(OptionT.none)))

    /** The empty service (all requests fallthrough).
      * @tparam F - Ignored
      * @tparam A - Ignored
      * @tparam I - Ignored
      * @return
      */
    def empty[F[_]: Applicative, A, I]: TSecAuthService[F, A, I] =
      Kleisli.lift(OptionT.none)
  }

}
