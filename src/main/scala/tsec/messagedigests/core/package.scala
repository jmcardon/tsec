package tsec.messagedigests

import java.nio.charset.Charset

import com.softwaremill.tagging._

package object core {

  type BytePickler[T]     = T => Array[Byte]
  type PickledLift[T]     = Array[Byte] => T
  type TaggedHasher[K, T] = Hasher[K] @@ T
  type CharEncoder[T]     = Charset @@ T
  type HashErr[T]         = Either[Throwable, T]

  sealed trait StringEncoding
  sealed trait UTF8  extends StringEncoding
  sealed trait UTF16 extends StringEncoding

  final case class DigestLift(list: List[Array[Byte]])      extends AnyVal
  final case class CryptoPickler[T](pickle: BytePickler[T]) extends AnyVal
  final case class Hasher[T](hasher: T)                     extends AnyVal

  object CryptoPickler {
    def stringPickle[S <: StringEncoding](charEncoder: CharEncoder[S]): CryptoPickler[String] =
      CryptoPickler[String](_.getBytes(charEncoder))
  }
}
