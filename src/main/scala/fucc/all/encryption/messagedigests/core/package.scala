package fucc.all.encryption.messagedigests

import java.nio.charset.Charset
import java.security.MessageDigest

import com.softwaremill.tagging._

package object core {

  type BytePickler[T] = T => Array[Byte]
  type PickledLift[T] = Array[Byte] => T
  type TaggedHasher[T] = MessageDigest @@ T
  type CharEncoder[T] = Charset @@ T

  sealed trait StringEncoding
  sealed trait UTF8 extends StringEncoding
  sealed trait UTF16 extends StringEncoding

  case class CryptoPickler[T](pickler: BytePickler[T]) extends AnyVal

  object CryptoPickler {
    def stringPickle[S <: StringEncoding](charEncoder: CharEncoder[S]): CryptoPickler[String  ] = CryptoPickler[String](_.getBytes(charEncoder))
  }

  val defaultStringEncoder: CryptoPickler[String] = CryptoPickler.stringPickle[UTF8](Charset.forName("UTF-8").taggedWith[UTF8])

}
