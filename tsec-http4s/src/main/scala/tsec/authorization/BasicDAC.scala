package tsec.authorization
import cats.MonadError
import cats.Eq
import cats.data.OptionT
import cats.syntax.all._
import tsec.authentication.SecuredRequest

/** A class modeling basic Discretionary access control.
  * In this case, the user has to provide an `AuthGroup` for which groups are allowed to access the data,
  *
  * @param eq
  * @tparam G
  */
abstract class BasicDAC[F[_], G, U](implicit eq: Eq[G], F: MonadError[F, Throwable]) extends Authorization[F, U] {
  def fetchGroup: F[AuthGroup[G]]

  def fetchOwner: F[G]

  def fetchAccess[Auth](u: SecuredRequest[F, Auth, U]): F[G]

  def isAuthorized[Auth](toAuth: SecuredRequest[F, Auth, U]): OptionT[F, SecuredRequest[F, Auth, U]] = {
    val out = for {
      owner  <- fetchOwner
      group  <- fetchGroup
      access <- fetchAccess[Auth](toAuth)
    } yield {
      if (eq.eqv(access, owner) || group.contains(access))
        Some(toAuth)
      else
        None
    }

    OptionT(out)
  }
}
