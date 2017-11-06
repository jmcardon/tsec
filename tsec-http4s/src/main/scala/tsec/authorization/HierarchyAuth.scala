package tsec.authorization

import cats.MonadError
import cats.data.OptionT
import tsec.authentication
import cats.syntax.functor._

sealed abstract case class HierarchyAuth[F[_], R, U](authLevel: R)(
    implicit role: AuthorizationInfo[F, R, U],
    enum: SimpleAuthEnum[R, Int],
    F: MonadError[F, Throwable]
) extends Authorization[F, U] {

  def isAuthorized[Auth](
      toAuth: authentication.SecuredRequest[F, Auth, U]
  ): OptionT[F, authentication.SecuredRequest[F, Auth, U]] =
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

  def apply[F[_], U, R](auth: R)(
      implicit role: AuthorizationInfo[F, R, U],
      e: SimpleAuthEnum[R, Int],
      F: MonadError[F, Throwable]
  ): F[HierarchyAuth[F, R, U]] =
    if (e.getRepr(auth) < 0)
      F.raiseError[HierarchyAuth[F, R, U]](InvalidAuthLevelError)
    else
      F.pure(new HierarchyAuth[F, R, U](auth) {})
}
