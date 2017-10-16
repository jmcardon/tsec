package tsec.authorization
import cats.MonadError
import cats.Eq
import cats.data.OptionT
import cats.syntax.all._
import tsec.authentication

abstract case class BasicDAC[U](group: AuthGroup[U])(implicit eq: Eq[U]) extends Authorization[U] {
  def fetchOwner[F[_]](implicit F: MonadError[F, Throwable]): F[U]
  def isAuthorized[F[_]](toAuth: U)(implicit F: MonadError[F, Throwable]): F[Boolean] =
    fetchOwner[F].map { o =>
      eq.eqv(toAuth, o) || group.contains(toAuth)
    }

  def isAuthorized[F[_], Auth](toAuth: authentication.SecuredRequest[F, Auth, U])(
      implicit F: MonadError[F, Throwable]
  ): OptionT[F, authentication.SecuredRequest[F, Auth, U]] =
    OptionT(fetchOwner[F].map { o =>
      if (eq.eqv(toAuth.identity, o) || group.contains(toAuth))
        Some(toAuth)
      else
        None
    })
}
