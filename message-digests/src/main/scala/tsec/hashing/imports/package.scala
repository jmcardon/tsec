package tsec.hashing

import cats.Id

package object imports {

  import java.security.MessageDigest

  import cats.Applicative
  import fs2.{Chunk, Pipe, Stream}
  import tsec.hashing.core._

  sealed class JHasher[F[_], A](
      implicit digestTag: JCADigestTag[A],
      F: Applicative[F]
  ) extends CryptoHasher[F, A] {

    private def genInstance = MessageDigest.getInstance(digestTag.algorithm)

    def hash(bytes: Array[Byte]): F[CryptoHash[A]] =
      F.pure(CryptoHash[A](genInstance.digest(bytes)))

    /** In this case, we use the same code as fs2, but we resolve
      * the hash string prefix from the implicit
      */
    def hashPipe: Pipe[F, Byte, Byte] =
      in =>
        Stream.suspend[F, Byte] {
          in.chunks
            .fold(genInstance) { (d, c) =>
              val bytes = c.toBytes
              d.update(bytes.values, bytes.offset, bytes.size)
              d
            }
            .flatMap { d =>
              Stream.chunk(Chunk.bytes(d.digest()))
            }
      }
  }

  implicit def genHasher[F[_]: Applicative, T: JCADigestTag]: CryptoHasher[F, T] =
    new JHasher[F, T]

  private[tsec] final class ArrayHashOps(val bytes: Array[Byte]) extends AnyVal {

    /** We are summoning an implicit for a particular A
      * using cats.Id here, given hashing in java is
      * pure
      */
    def hash[A](implicit C: CryptoHasher[Id, A], J: JCADigestTag[A]): CryptoHash[A] =
      C.hash(bytes)
  }

  implicit final def hashOps(value: Array[Byte]): ArrayHashOps = new ArrayHashOps(value)

}
