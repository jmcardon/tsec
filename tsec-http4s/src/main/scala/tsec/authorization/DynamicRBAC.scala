package tsec.authorization

import cats.MonadError
import cats.data.OptionT
import tsec.authentication
import cats.syntax.all._

class DynamicRBAC[F[_], U, Role](
    implicit authInfo: AuthorizationInfo[F, U, Role],
    dynamic: DynamicAuthGroup[F, U, Role],
    enum: SimpleAuthEnum[Role, String],
    F: MonadError[F, Throwable]
) extends Authorization[F, U] {
  def isAuthorized[Auth](
      toAuth: authentication.SecuredRequest[F, Auth, U]
  ): OptionT[F, authentication.SecuredRequest[F, Auth, U]] =
    OptionT(for {
      info  <- authInfo.fetchInfo(toAuth.identity)
      group <- dynamic.fetchGroupInfo(toAuth.identity)
    } yield {
      if (enum.contains(info) && group.contains(info))
        Some(toAuth)
      else
        None
    })

}

object DynamicRBAC {
  def apply[F[_], U, Role](
      implicit authInfo: AuthorizationInfo[F, U, Role],
      dynamic: DynamicAuthGroup[F, U, Role],
      enum: SimpleAuthEnum[Role, String],
      F: MonadError[F, Throwable]
  ): DynamicRBAC[F, U, Role] = new DynamicRBAC[F, U, Role]()
}
