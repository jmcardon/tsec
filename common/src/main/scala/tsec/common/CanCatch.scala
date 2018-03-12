package tsec.common

private[tsec] trait CanCatch[F[_]] {
  def catchF[C](thunk: => C): F[C]
}
