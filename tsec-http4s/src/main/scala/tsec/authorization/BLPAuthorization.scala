package tsec.authorization

import cats.MonadError
import cats.data.OptionT
import tsec.authentication
import cats.syntax.functor._

/** A trait representing Bell LaPadula Model Authorization
  * We will use the strong star property here, thus:
  * No reading a higher authorization level
  * Only writing to your authorization level.
  * We will not use DAC here, though this could be implemented
  *
  */
trait BLPAuthorization[F[_], A] extends Authorization[F, A]

/** Bell La Padula read action: We do not read to higher authorization levels aka Simple Security Property.
  * For our model, we will think about higher authorization levels as being lower in number
  *
  */
sealed abstract case class BLPReadAction[F[_], Role, A](authLevel: Role)(
    implicit authInfo: AuthorizationInfo[F, Role, A],
    enum: SimpleAuthEnum[Role, Int],
    F: MonadError[F, Throwable]
) extends BLPAuthorization[F, A] {
  def isAuthorized[Auth](
      toAuth: authentication.SecuredRequest[F, Auth, A]
  ): OptionT[F, authentication.SecuredRequest[F, Auth, A]] = {
    val out = authInfo.fetchInfo(toAuth.identity).map { info =>
      val userAuthLevel = enum.getRepr(info)
      if (enum.contains(info) && userAuthLevel <= enum.getRepr(authLevel))
        Some(toAuth)
      else
        None
    }
    OptionT(out)
  }
}

object BLPReadAction {
  def apply[F[_], Role, A](authLevel: Role)(
      implicit authInfo: AuthorizationInfo[F, Role, A],
      enum: SimpleAuthEnum[Role, Int],
      F: MonadError[F, Throwable]
  ): F[BLPReadAction[F, Role, A]] =
    if (enum.getRepr(authLevel) < 0)
      F.raiseError(InvalidAuthLevelError)
    else
      F.pure(new BLPReadAction[F, Role, A](authLevel) {})

}

/** Only write to same level. No write up, no write down.
  *
  */
sealed abstract case class BLPWriteAction[F[_], Role, A](authLevel: Role)(
    implicit authInfo: AuthorizationInfo[F, Role, A],
    enum: SimpleAuthEnum[Role, Int],
    F: MonadError[F, Throwable]
) extends BLPAuthorization[F, A] {
  def isAuthorized[Auth](
      toAuth: authentication.SecuredRequest[F, Auth, A]
  ): OptionT[F, authentication.SecuredRequest[F, Auth, A]] = {
    val out = authInfo.fetchInfo(toAuth.identity).map { info =>
      val userAuthLevel = enum.getRepr(info)
      if (enum.contains(info) && userAuthLevel == enum.getRepr(authLevel))
        Some(toAuth)
      else
        None
    }
    OptionT(out)
  }
}

object BLPWriteAction {
  def apply[F[_], Role, A](authLevel: Role)(
      implicit authInfo: AuthorizationInfo[F, Role, A],
      enum: SimpleAuthEnum[Role, Int],
      F: MonadError[F, Throwable]
  ): F[BLPWriteAction[F, Role, A]] =
    if (enum.getRepr(authLevel) < 0)
      F.raiseError(InvalidAuthLevelError)
    else
      F.pure(new BLPWriteAction[F, Role, A](authLevel) {})
}
