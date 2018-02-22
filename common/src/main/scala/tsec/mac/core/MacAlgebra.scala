package tsec.mac.core

import cats.effect.Sync

trait MacAlgebra[A, MK[_], S] {

  def sign[F[_]](in: Array[Byte], key: MK[A])(implicit F: Sync[F], S: S): F[MAC[A]]

  def verify[F[_]](in: Array[Byte], hashed: MAC[A], key: MK[A])(
      implicit F: Sync[F],
      S: S
  ): F[Boolean]

}
