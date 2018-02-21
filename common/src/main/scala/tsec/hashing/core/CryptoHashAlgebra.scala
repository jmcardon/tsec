package tsec.hashing.core

import cats.effect.Sync
import fs2.Pipe

trait CryptoHashAlgebra[A, S[_[_]]] {

  def hash[F[_]](bytes: Array[Byte])(implicit F: Sync[F], S: S[F]): F[CryptoHash[A]]

  def hashPipe[F[_]](implicit F: Sync[F], S: S[F]): Pipe[F, Byte, Byte]

}
