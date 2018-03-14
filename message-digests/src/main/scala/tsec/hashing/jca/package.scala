package tsec.hashing

import java.security.MessageDigest

import cats.effect.IO
import cats.{Applicative, Id}
import fs2.{Chunk, Pipe, Stream}
import tsec.common.CryptoTag

package object jca {

  trait JCADigestTag[T] extends CryptoTag[T]

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

  @deprecated(
    """This (lame) abstraction is essentially serialization
       and doesn't deservce its own type. There's very little
       use for cryptographically hashing arbitrary objects.
       As such, this isn't necessay
    """.stripMargin,
    "0.0.1-M11"
  )
  case class CryptoPickler[A](pickle: A => Array[Byte])

  object JHasher {

    @deprecated(""" Use [Algorithm].hash[Id]
      """.stripMargin, "0.0.1-M11")
    def hash[C, T](toHash: C)(implicit P: CryptoPickler[C], hasher: JHasher[Id, T]): CryptoHash[T] =
      hasher.hash(P.pickle(toHash))

    @deprecated(""" Use [Algorithm].hash[Id]
      """.stripMargin, "0.0.1-M11")
    def hashBytes[T](bytes: Array[Byte])(implicit hasher: JHasher[Id, T]): CryptoHash[T] =
      hasher.hash(bytes)

    @deprecated(""" Use [Algorithm].hash[Id]
      """.stripMargin, "0.0.1-M11")
    def hashToByteArray[T](bytes: Array[Byte])(implicit hasher: JHasher[Id, T]): Array[Byte] =
      hasher.hash(bytes)

    @deprecated("Lord almighty just avoid doing this.", "0.0.1-M11")
    def combineAndHash[C, T](
        toHash: cats.data.NonEmptyList[C]
    )(implicit P: CryptoPickler[C], hasher: JHasher[IO, T]): CryptoHash[T] =
      CryptoHash[T](
        fs2.Stream
          .emits(toHash.toList.flatMap(P.pickle(_).toList))
          .covary[IO]
          .through(hasher.hashPipe)
          .compile
          .toList
          .unsafeRunSync()
          .toArray
      )

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
