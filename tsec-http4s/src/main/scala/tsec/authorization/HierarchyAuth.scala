package tsec.authorization

import cats.MonadError
import cats.data.OptionT
import tsec.authentication

sealed abstract case class HierarchyAuth[U, R](authLevel: Int)(
    implicit role: AuthorizationInfo[U, R],
    enum: SimpleAuthEnum[R, Int]
) extends Authorization[U] {

  def isAuthorized[F[_], Auth](toAuth: authentication.SecuredRequest[F, Auth, U])(
      implicit F: MonadError[F, Throwable]
  ): OptionT[F, authentication.SecuredRequest[F, Auth, U]] = {
    val authRole = role.getRole(toAuth.identity)
    val intRepr  = enum.getRepr(authRole)
    if (0 <= intRepr && intRepr <= authLevel && enum.contains(authRole))
      OptionT.pure[F](toAuth)
    else
      OptionT.none
  }
}

object HierarchyAuth {
  type SubZeroAuthError = SubZeroAuthError.type

  final object SubZeroAuthError extends Exception {
    override def getMessage: String = "The minimum auth level is zero."

    override def fillInStackTrace(): Throwable = this
  }

  def apply[U, R](auth: Int)(
      implicit role: AuthorizationInfo[U, R],
    e: SimpleAuthEnum[R, Int]
  ): Either[SubZeroAuthError, HierarchyAuth[U, R]] =
    if (auth < 0)
      Left(SubZeroAuthError)
    else
      Right(new HierarchyAuth[U, R](auth) {})
}
