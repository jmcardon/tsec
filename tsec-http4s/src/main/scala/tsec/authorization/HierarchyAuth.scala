package tsec.authorization

import cats.MonadError
import cats.data.OptionT
import cats.syntax.functor._
import tsec.authentication

sealed abstract case class HierarchyAuth[F[_], R, U, Auth](authLevel: R)(
    implicit role: AuthorizationInfo[F, R, U],
    enum: SimpleAuthEnum[R, Int],
    F: MonadError[F, Throwable]
) extends Authorization[F, U, Auth] {

  def isAuthorized(
      toAuth: authentication.SecuredRequest[F, U, Auth]
  ): OptionT[F, authentication.SecuredRequest[F, U, Auth]] =
    OptionT {
      role.fetchInfo(toAuth.identity).map { authRole =>
        val intRepr = enum.getRepr(authRole)
        if (0 <= intRepr && intRepr <= enum.getRepr(authLevel) && enum.contains(authRole))
          Some(toAuth)
        else
          None
      }
    }
}

object HierarchyAuth {

  def apply[F[_], R, U, Auth](auth: R)(
      implicit role: AuthorizationInfo[F, R, U],
      e: SimpleAuthEnum[R, Int],
      F: MonadError[F, Throwable]
  ): F[HierarchyAuth[F, R, U, Auth]] =
    if (e.getRepr(auth) < 0)
      F.raiseError[HierarchyAuth[F, R, U, Auth]](InvalidAuthLevelError)
    else
      F.pure(new HierarchyAuth[F, R, U, Auth](auth) {})
}
