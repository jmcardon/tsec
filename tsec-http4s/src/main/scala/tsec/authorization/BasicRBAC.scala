package tsec.authorization

import cats.MonadError
import cats.data.OptionT
import tsec.authentication
import cats.syntax.functor._

import scala.reflect.ClassTag

sealed abstract case class BasicRBAC[F[_], R, U, Auth](authorized: AuthGroup[R])(
    implicit role: AuthorizationInfo[F, R, U],
    enum: SimpleAuthEnum[R, String],
    F: MonadError[F, Throwable]
) extends Authorization[F, U, Auth] {

  def isAuthorized(
      toAuth: authentication.SecuredRequest[F, U, Auth]
  ): OptionT[F, authentication.SecuredRequest[F, U, Auth]] =
    OptionT {
      role.fetchInfo(toAuth.identity).map { extractedRole =>
        if (enum.contains(extractedRole) && authorized.contains(extractedRole))
          Some(toAuth)
        else
          None
      }
    }
}

object BasicRBAC {
  def apply[F[_], R: ClassTag, U, Auth](roles: R*)(
      implicit enum: SimpleAuthEnum[R, String],
      role: AuthorizationInfo[F, R, U],
      F: MonadError[F, Throwable]
  ): BasicRBAC[F, R, U, Auth] =
    fromGroup[F, R, U, Auth](AuthGroup(roles: _*))

  def fromGroup[F[_], R: ClassTag, U, Auth](valueSet: AuthGroup[R])(
      implicit role: AuthorizationInfo[F, R, U],
      enum: SimpleAuthEnum[R, String],
      F: MonadError[F, Throwable]
  ): BasicRBAC[F, R, U, Auth] = new BasicRBAC[F, R, U, Auth](valueSet) {}

  def all[F[_], R: ClassTag, U, Auth](
      implicit enum: SimpleAuthEnum[R, String],
      role: AuthorizationInfo[F, R, U],
      F: MonadError[F, Throwable]
  ): BasicRBAC[F, R, U, Auth] =
    new BasicRBAC[F, R, U, Auth](enum.viewAll) {}
}
