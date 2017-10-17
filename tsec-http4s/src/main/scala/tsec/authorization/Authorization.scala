package tsec.authorization

import cats.data.OptionT
import tsec.authentication.SecuredRequest

trait Authorization[F[_], Identity] {
  def isAuthorized[Auth](toAuth: SecuredRequest[F, Auth, Identity]): OptionT[F, SecuredRequest[F, Auth, Identity]]
}
