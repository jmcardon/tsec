package tsec.authorization

import cats.MonadError
import cats.data.OptionT
import tsec.authentication
import cats.syntax.functor._

import scala.reflect.ClassTag

sealed abstract case class BasicRBAC[F[_], U, R](authorized: AuthGroup[R])(
    implicit role: AuthorizationInfo[F, U, R],
    enum: SimpleAuthEnum[R, String],
    F: MonadError[F, Throwable]
) extends Authorization[F, U] {

  def isAuthorized[Auth](
      toAuth: authentication.SecuredRequest[F, Auth, U]
  ): OptionT[F, authentication.SecuredRequest[F, Auth, U]] =
    OptionT {
      role.getRole(toAuth.identity).map { extractedRole =>
        if (enum.contains(extractedRole) && authorized.contains(extractedRole))
          Some(toAuth)
        else
          None
      }
    }
}

object BasicRBAC {
  def apply[F[_], U, R: ClassTag](roles: R*)(
      implicit enum: SimpleAuthEnum[R, String],
      role: AuthorizationInfo[F, U, R],
      F: MonadError[F, Throwable]
  ): BasicRBAC[F, U, R] =
    fromGroup[F, U, R](AuthGroup(roles: _*))

  def fromGroup[F[_], U, R: ClassTag](valueSet: AuthGroup[R])(
      implicit role: AuthorizationInfo[F, U, R],
      enum: SimpleAuthEnum[R, String],
      F: MonadError[F, Throwable]
  ): BasicRBAC[F, U, R] = new BasicRBAC[F, U, R](valueSet) {}

  def all[F[_], U, R: ClassTag](
      implicit enum: SimpleAuthEnum[R, String],
      role: AuthorizationInfo[F, U, R],
      F: MonadError[F, Throwable]
  ): BasicRBAC[F, U, R] =
    new BasicRBAC[F, U, R](enum.viewAll) {}
}
