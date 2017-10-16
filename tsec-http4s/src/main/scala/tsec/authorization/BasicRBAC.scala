package tsec.authorization

import cats.MonadError
import cats.data.OptionT
import tsec.authentication

import scala.reflect.ClassTag

sealed abstract case class BasicRBAC[U, R](authorized: AuthGroup[R])(
    implicit role: AuthorizationInfo[U, R],
    enum: SimpleAuthEnum[R, String]
) extends Authorization[U] {

  def isAuthorized[F[_], Auth](toAuth: authentication.SecuredRequest[F, Auth, U])(
      implicit F: MonadError[F, Throwable]
  ): OptionT[F, authentication.SecuredRequest[F, Auth, U]] = {
    val extractedRole: R = role.getRole(toAuth.identity)
    if (enum.contains(extractedRole) && authorized.contains(extractedRole))
      OptionT.pure[F](toAuth)
    else
      OptionT.none
  }
}

object BasicRBAC {
  def apply[U, R: ClassTag](
      roles: R*
  )(implicit enum: SimpleAuthEnum[R, String], role: AuthorizationInfo[U, R]): BasicRBAC[U, R] =
    fromGroup[U, R](AuthGroup(roles: _*))

  def fromGroup[U, R: ClassTag](valueSet: AuthGroup[R])(
      implicit role: AuthorizationInfo[U, R],
      enum: SimpleAuthEnum[R, String]
  ): BasicRBAC[U, R] = new BasicRBAC[U, R](valueSet) {}

  def all[U, R: ClassTag](implicit enum: SimpleAuthEnum[R, String], role: AuthorizationInfo[U, R]): BasicRBAC[U, R] =
    new BasicRBAC[U, R](AuthGroup.fromSeq[R](enum.viewAll)) {}
}
