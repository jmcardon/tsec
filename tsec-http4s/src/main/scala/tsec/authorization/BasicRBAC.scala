package tsec.authorization

import cats.MonadError
import cats.data.OptionT
import tsec.authentication
import cats.syntax.functor._

import scala.reflect.ClassTag

sealed abstract case class BasicRBAC[F[_], R, U](authorized: AuthGroup[R])(
    implicit role: AuthorizationInfo[F, R, U],
    enum: SimpleAuthEnum[R, String],
    F: MonadError[F, Throwable]
) extends Authorization[F, U] {

  def isAuthorized[Auth](
      toAuth: authentication.SecuredRequest[F, Auth, U]
  ): OptionT[F, authentication.SecuredRequest[F, Auth, U]] =
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
  def apply[F[_], R: ClassTag, U](roles: R*)(
      implicit enum: SimpleAuthEnum[R, String],
      role: AuthorizationInfo[F, R, U],
      F: MonadError[F, Throwable]
  ): BasicRBAC[F, R, U] =
    fromGroup[F, R, U](AuthGroup(roles: _*))

  def fromGroup[F[_], R: ClassTag, U](valueSet: AuthGroup[R])(
      implicit role: AuthorizationInfo[F, R, U],
      enum: SimpleAuthEnum[R, String],
      F: MonadError[F, Throwable]
  ): BasicRBAC[F, R, U] = new BasicRBAC[F, R, U](valueSet) {}

  def all[F[_], R: ClassTag, U](
      implicit enum: SimpleAuthEnum[R, String],
      role: AuthorizationInfo[F, R, U],
      F: MonadError[F, Throwable]
  ): BasicRBAC[F, R, U] =
    new BasicRBAC[F, R, U](enum.viewAll) {}
}
