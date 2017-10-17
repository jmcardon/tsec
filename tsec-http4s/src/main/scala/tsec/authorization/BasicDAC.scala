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
  * @tparam U
  */
abstract class BasicDAC[F[_], U](implicit eq: Eq[U], F: MonadError[F, Throwable]) extends Authorization[F, U] {
  def fetchGroup(u: U): F[AuthGroup[U]]

  def fetchOwner[Auth](toAuth: SecuredRequest[F, Auth, U]): F[U]

  def isAuthorized[Auth](toAuth: SecuredRequest[F, Auth, U]): OptionT[F, SecuredRequest[F, Auth, U]] = {
    val out = for {
      owner <- fetchOwner[Auth](toAuth)
      group <- fetchGroup(toAuth.identity)
    } yield {
      if (eq.eqv(toAuth.identity, owner) || group.contains(toAuth))
        Some(toAuth)
      else
        None
    }

    OptionT(out)
  }
}
