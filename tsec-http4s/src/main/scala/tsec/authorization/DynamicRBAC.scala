package tsec.authorization

import cats.MonadError
import cats.data.OptionT
import tsec.authentication
import cats.syntax.all._

case class DynamicRBAC[F[_], Role, U, Auth](dynamic: DynamicAuthGroup[F, Role])(
    implicit authInfo: AuthorizationInfo[F, Role, U],
    enum: SimpleAuthEnum[Role, String],
    F: MonadError[F, Throwable]
) extends Authorization[F, U, Auth] {
  def isAuthorized(
      toAuth: authentication.SecuredRequest[F, U, Auth]
  ): OptionT[F, authentication.SecuredRequest[F, U, Auth]] =
    OptionT(for {
      info  <- authInfo.fetchInfo(toAuth.identity)
      group <- dynamic.fetchGroupInfo
    } yield {
      if (enum.contains(info) && group.contains(info))
        Some(toAuth)
      else
        None
    })
}
