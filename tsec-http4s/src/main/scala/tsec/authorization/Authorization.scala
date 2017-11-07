package tsec.authorization

import cats.Monad
import cats.data.OptionT
import cats.kernel.Monoid
import tsec.authentication.SecuredRequest

trait Authorization[F[_], Identity, Auth] {
  def isAuthorized(toAuth: SecuredRequest[F, Identity, Auth]): OptionT[F, SecuredRequest[F, Identity, Auth]]
}

object Authorization {
  implicit def authorizationMonoid[F[_]: Monad, I, Auth]: Monoid[Authorization[F, I, Auth]] =
    new Monoid[Authorization[F, I, Auth]] {
      def empty: Authorization[F, I, Auth] = new Authorization[F, I, Auth] {

        def isAuthorized(toAuth: SecuredRequest[F, I, Auth]): OptionT[F, SecuredRequest[F, I, Auth]] =
          OptionT.pure(toAuth)
      }

      def combine(x: Authorization[F, I, Auth], y: Authorization[F, I, Auth]): Authorization[F, I, Auth] =
        new Authorization[F, I, Auth] {
          def isAuthorized(toAuth: SecuredRequest[F, I, Auth]): OptionT[F, SecuredRequest[F, I, Auth]] =
            x.isAuthorized(toAuth).flatMap(y.isAuthorized)
        }
    }
}
