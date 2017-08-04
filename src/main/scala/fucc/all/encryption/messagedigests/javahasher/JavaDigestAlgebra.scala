package fucc.all.encryption.messagedigests.javahasher

import cats.Monoid
import cats.effect.IO
import cats.instances.byte
import fucc.all.encryption.messagedigests.core._

class JavaDigestAlgebra[T <: HashAlgorithm: HashTag](implicit hasher: PureHasher[T]) extends DigestAlgebra[IO, T] {
  type S = Array[Byte]

  override implicit def monoid: Monoid[Array[Byte]] = new Monoid[Array[Byte]]{
    def empty: Array[Byte] = Array.empty[Byte]

    def combine(x: Array[Byte], y: Array[Byte]): Array[Byte] = x ++ y
  }

  def liftS(s: Array[Byte]): Array[Byte] = s

  def hash(s: Array[Byte]): IO[Array[Byte]] = IO(hasher.hashToBytes(s))

  def consume(state: Array[Byte]): IO[Array[Byte]] = hash(state)
}
