package tsec

import java.nio.charset.{Charset, StandardCharsets}
import tsec.messagedigests.imports.JHasher

package object messagedigests {
  type BytePickler[T] = T => Array[Byte]

  sealed trait StringEncoding[A] {
    def getCharset: Charset
  }
  sealed trait UTF8

  implicit object UTF8 extends StringEncoding[UTF8] {
    def getCharset: Charset = StandardCharsets.UTF_8
  }

  sealed trait UTF16
  implicit object UTF16 extends StringEncoding[UTF16]{
    def getCharset: Charset = StandardCharsets.UTF_16
  }

  sealed trait ASCII

  implicit object ASCII extends StringEncoding[ASCII]{
    def getCharset: Charset = StandardCharsets.US_ASCII
  }

  sealed trait ISO_8859_1

  implicit object ISO_8859_1 extends StringEncoding[ISO_8859_1]{
    def getCharset: Charset = StandardCharsets.ISO_8859_1
  }

  final case class DigestLift(list: List[Array[Byte]])      extends AnyVal
  final case class CryptoPickler[T](pickle: BytePickler[T]) extends AnyVal

  object CryptoPickler {
    def stringPickle[S](implicit s: StringEncoding[S]): CryptoPickler[String] =
      CryptoPickler[String](_.getBytes(s.getCharset))
  }

  class DigestOps[T](val c: T) extends AnyVal {
    def pickleAndHash[K](implicit jHasher: JHasher[K], pickler: CryptoPickler[T]): K = jHasher.hash(c)
  }

  implicit def digestOps[T: CryptoPickler](c: T): DigestOps[T] = new DigestOps[T](c)

  class ArrayDigestOps(val arr: Array[Byte]) extends AnyVal {
    def hash[K](implicit jHasher: JHasher[K]): K                  = jHasher.hashBytes(arr)
    def hashToArray[K](implicit jHasher: JHasher[K]): Array[Byte] = jHasher.hashToByteArray(arr)
  }

  implicit def arrayOps(array: Array[Byte]): ArrayDigestOps = new ArrayDigestOps(array)

}
