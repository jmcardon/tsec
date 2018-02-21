package tsec.mac.core

import cats.effect.Sync

trait MacAlgebra[A, MK[_], S[_[_]]] {

  def sign[F[_]](in: Array[Byte], key: MK[A])(implicit F: Sync[F], S: S[F]): F[MAC[A]]

  def verify[F[_]](in: Array[Byte], hashed: MAC[A], key: MK[A])(
      implicit F: Sync[F],
      S: S[F]
  ): F[Boolean]

  def generateKey[F[_]](implicit F: Sync[F], S: S[F]): F[MK[A]]

}
