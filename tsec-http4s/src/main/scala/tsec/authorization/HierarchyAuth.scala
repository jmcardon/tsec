package tsec.authorization

import cats.MonadError
import cats.data.OptionT
import tsec.authentication
import cats.syntax.functor._

sealed abstract case class HierarchyAuth[F[_], U, R](authLevel: Int)(
    implicit role: AuthorizationInfo[F, U, R],
    enum: SimpleAuthEnum[R, Int],
    F: MonadError[F, Throwable]
) extends Authorization[F, U] {

  def isAuthorized[Auth](
      toAuth: authentication.SecuredRequest[F, Auth, U]
  ): OptionT[F, authentication.SecuredRequest[F, Auth, U]] =
    OptionT {
      role.fetchInfo(toAuth.identity).map { authRole =>
        val intRepr = enum.getRepr(authRole)
        if (0 <= intRepr && intRepr <= authLevel && enum.contains(authRole))
          Some(toAuth)
        else
          None
      }
    }
}

object HierarchyAuth {

  def apply[F[_], U, R](auth: Int)(
      implicit role: AuthorizationInfo[F, U, R],
      e: SimpleAuthEnum[R, Int],
      F: MonadError[F, Throwable]
  ): F[HierarchyAuth[F, U, R]] =
    if (auth < 0)
      F.raiseError[HierarchyAuth[F, U, R]](InvalidAuthLevelError)
    else
      F.pure(new HierarchyAuth[F, U, R](auth) {})
}
