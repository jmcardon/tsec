package tsec.cipher.symmetric.core

import cats.effect.Sync

trait IvStrategy[A] {

  def genIv[F[_]](implicit F: Sync[F]): F[Iv[A]]

  def genIvUnsafe: Iv[A]

}