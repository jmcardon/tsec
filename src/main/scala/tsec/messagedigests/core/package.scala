package tsec.messagedigests

import java.nio.charset.Charset
import shapeless.tag.@@

package object core {

  type BytePickler[T]     = T => Array[Byte]
  type PickledLift[T]     = Array[Byte] => T
  type HashErr[T]         = Either[Throwable, T]

  sealed trait StringEncoding
  sealed trait UTF8  extends StringEncoding
  sealed trait UTF16 extends StringEncoding

  final case class DigestLift(list: List[Array[Byte]])      extends AnyVal
  final case class CryptoPickler[T](pickle: BytePickler[T]) extends AnyVal

  object CryptoPickler {
    def stringPickle[S <: StringEncoding](charEncoder: Charset @@ S): CryptoPickler[String] =
      CryptoPickler[String](_.getBytes(charEncoder))
  }
}
