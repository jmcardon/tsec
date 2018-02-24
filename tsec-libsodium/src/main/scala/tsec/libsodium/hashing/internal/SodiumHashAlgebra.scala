package tsec.libsodium.hashing.internal

import cats.effect.Sync
import fs2.Pipe
import tsec.hashing.core.CryptoHash
import tsec.libsodium.ScalaSodium

trait SodiumHashAlgebra[A] {

  def hash[F[_]](bytes: Array[Byte])(implicit F: Sync[F], S: ScalaSodium): F[CryptoHash[A]]

  def hashPipe[F[_]](implicit F: Sync[F], S: ScalaSodium): Pipe[F, Byte, Byte]

}
