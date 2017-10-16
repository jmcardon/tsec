package tsec.authorization

import cats.MonadError
import cats.data.OptionT
import tsec.authentication.SecuredRequest

trait Authorization[Identity] {
  def isAuthorized[F[_], Auth](toAuth: SecuredRequest[F, Auth, Identity])(
      implicit F: MonadError[F, Throwable]
  ): OptionT[F, SecuredRequest[F, Auth, Identity]]
}
