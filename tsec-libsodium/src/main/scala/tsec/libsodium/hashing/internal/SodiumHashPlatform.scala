package tsec.libsodium.hashing.internal

import cats.Id
import cats.effect.Sync
import fs2._
import tsec.hashing._
import tsec.libsodium.ScalaSodium
import tsec.libsodium.hashing._

trait SodiumHashPlatform[A] extends SodiumHash[A] with SodiumHashAPI[A] {
  implicit val sodiumHash: SodiumHash[A]           = this
  implicit val sodiumHashAlgebra: SodiumHashAPI[A] = this

  implicit def hasher[F[_]](implicit F: Sync[F], S: ScalaSodium): CryptoHasher[F, A] =
    new CryptoHasher[F, A] {
      def hash(bytes: Array[Byte]): F[CryptoHash[A]] = F.delay(impl.unsafeHash(bytes))

      def hashPipe: Pipe[F, Byte, Byte] = impl.hashPipe[F]
    }

  implicit def idHasher(implicit S: ScalaSodium): CryptoHasher[Id, A] =
    new CryptoHasher[Id, A] {
      def hash(bytes: Array[Byte]): Id[CryptoHash[A]] = impl.unsafeHash(bytes)

      /** I hope to god no one
        * actually ever uses this
        *
        * If you do, god save you friend.
        */
      def hashPipe: Pipe[Id, Byte, Byte] =
        in =>
          Stream.suspend[Id, Byte] {
            for {
              rawState <- Stream.suspend(Stream.emit {
                val state = HashState[A](new Array[Byte](stateSize))
                sodiumHashInit(state)
                state
              })
              ast <- in.chunks.fold(rawState) { (st, in) =>
                sodiumHashChunk(st, in.toBytes.toArray)
                st
              }
              out <- Stream.suspend(Stream.emit {
                val out = new Array[Byte](hashLen)
                sodiumHashFinal(ast, out)
                out
              })
              c <- Stream.chunk(Chunk.bytes(out)).covary[Id]
            } yield c
        }

    }

  object impl {
    def unsafeHash(bytes: Array[Byte])(implicit S: ScalaSodium): CryptoHash[A] = {
      val out = new Array[Byte](hashLen)
      sodiumHash(bytes, out)
      CryptoHash[A](out)
    }

    final def hashPipe[F[_]](implicit F: Sync[F], S: ScalaSodium): Pipe[F, Byte, Byte] = { in =>
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
}
