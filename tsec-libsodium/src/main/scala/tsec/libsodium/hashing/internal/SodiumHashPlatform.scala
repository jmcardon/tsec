package tsec.libsodium.hashing.internal

import cats.effect.Sync
import fs2._
import tsec.libsodium.ScalaSodium
import tsec.libsodium.hashing.{Hash, HashState}

trait SodiumHashPlatform[A] extends SodiumHash[A] with SodiumHashAlgebra[A] {
  implicit val sodiumHash: SodiumHash[A]               = this
  implicit val sodiumHashAlgebra: SodiumHashAlgebra[A] = this

  def hash[F[_]](bytes: Array[Byte])(implicit F: Sync[F], S: ScalaSodium): F[Hash[A]] = F.delay {
    val out = new Array[Byte](hashLen)
    sodiumHash(bytes, out)
    Hash[A](out)
  }

  def hashPipe[F[_]](implicit F: Sync[F], S: ScalaSodium): Pipe[F, Byte, Byte] = { in =>
    Stream.suspend[F, Byte] {
      for {
        rawState <- Stream.eval(F.delay {
          val state = HashState[A](new Array[Byte](stateSize))
          sodiumHashInit(state)
          state
        })
        ast <- in.chunks.fold(rawState) { (st, in) =>
          sodiumHashChunk(st, in.toBytes.toArray)
          st
        }
        out <- Stream.eval(F.delay {
          val out = new Array[Byte](hashLen)
          sodiumHashFinal(ast, out)
          out
        })
        c <- Stream.chunk(Chunk.bytes(out)).covary[F]
      } yield c
    }
  }
}
