package tsec.libsodium.hashing.internal

import tsec.libsodium.hashing._
import cats.effect.Sync
import fs2.Pipe
import tsec.libsodium.ScalaSodium

trait SodiumHashAlgebra[A] {

  def hash[F[_]](bytes: Array[Byte])(implicit F: Sync[F], S: ScalaSodium): F[Hash[A]]

  def hashPipe[F[_]](implicit F: Sync[F], S: ScalaSodium): Pipe[F, Byte, Byte]

}
