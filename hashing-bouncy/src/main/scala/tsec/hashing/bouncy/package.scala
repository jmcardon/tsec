package tsec.hashing

import java.security.MessageDigest

import cats.Applicative
import fs2.{Chunk, Pipe, Stream}
import tsec.Bouncy
import tsec.common.CryptoTag

package object bouncy {

  trait BouncyDigestTag[T] extends CryptoTag[T]

  sealed class BouncyHasher[F[_], A](
      implicit digestTag: BouncyDigestTag[A],
      F: Applicative[F]
  ) extends CryptoHasher[F, A] {

    private def genInstance = MessageDigest.getInstance(digestTag.algorithm, "BC")

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

  @deprecated(
    """This (lame) abstraction is essentially serialization
       and doesn't deservce its own type. There's very little
       use for cryptographically hashing arbitrary objects.
       As such, this isn't necessay
    """.stripMargin,
    "0.0.1-M11"
  )
  case class CryptoPickler[A](pickle: A => Array[Byte])

  implicit def genHasher[F[_]: Applicative, T: BouncyDigestTag](implicit B: Bouncy): CryptoHasher[F, T] =
    new BouncyHasher[F, T]

}
