package tsec.authorization

import cats.Monad
import cats.data.OptionT
import cats.kernel.Monoid
import tsec.authentication.SecuredRequest

trait Authorization[F[_], Identity] {
  def isAuthorized[Auth](toAuth: SecuredRequest[F, Auth, Identity]): OptionT[F, SecuredRequest[F, Auth, Identity]]
}

object Authorization {
  implicit def authorizationMonoid[F[_]: Monad, I]: Monoid[Authorization[F, I]] = new Monoid[Authorization[F, I]] {
    def empty: Authorization[F, I] = new Authorization[F, I] {
      def isAuthorized[Auth](toAuth: SecuredRequest[F, Auth, I]): OptionT[F, SecuredRequest[F, Auth, I]] =
        OptionT.pure(toAuth)
    }

    def combine(x: Authorization[F, I], y: Authorization[F, I]): Authorization[F, I] = new Authorization[F, I] {
      def isAuthorized[Auth](toAuth: SecuredRequest[F, Auth, I]): OptionT[F, SecuredRequest[F, Auth, I]] =
        x.isAuthorized(toAuth).flatMap(y.isAuthorized)
    }
  }
}
