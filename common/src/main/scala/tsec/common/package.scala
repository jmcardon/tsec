package tsec

import java.nio.charset.StandardCharsets
import java.util.Base64

import cats.evidence.Is

package object common {

  trait ByteEV[A] {

    def fromArray(array: Array[Byte]): A

    def toArray(a: A): Array[Byte]

  }

  trait TaggedByteArray {
    type I <: Array[Byte]

    val is: Is[I, Array[Byte]]
  }

  trait StringEV[A] {

    def fromString(a: String): A

    def asString(a: A): String

  }

  trait TaggedString {
    type I <: String

    val is: Is[I, String]
  }

  class TaggedByteSyntax[A](val repr: A) extends AnyVal {
    def toArray(implicit byteEV: ByteEV[A]): Array[Byte] = byteEV.toArray(repr)
  }

  class TaggedStringSyntax[A](val repr: A) extends AnyVal {
    def asString(implicit stringEV: StringEV[A]): String = stringEV.asString(repr)
  }

  final class JerryStringer(val s: String) extends AnyVal {
    def utf8Bytes: Array[Byte]   = s.getBytes(StandardCharsets.UTF_8)
    def asciiBytes: Array[Byte]  = s.getBytes(StandardCharsets.US_ASCII)
    def base64Bytes: Array[Byte] = Base64.getDecoder.decode(s)
    def base64UrlBytes: Array[Byte] = Base64.getUrlDecoder.decode(s)
    def toStringRepr[A](implicit stringEV: StringEV[A]): A = stringEV.fromString(s)
  }

  final class ByteSyntaxHelpers(val array: Array[Byte]) extends AnyVal {
    def toUtf8String           = new String(array, StandardCharsets.UTF_8)
    def toAsciiString          = new String(array, StandardCharsets.US_ASCII)
    def toB64UrlString: String = Base64.getUrlEncoder.encodeToString(array)
    def toB64String: String    = Base64.getEncoder.encodeToString(array)
    def toRepr[A](implicit byteEV: ByteEV[A]): A = byteEV.fromArray(array)
  }

  implicit final def byteSyntaxOps(array: Array[Byte]) = new ByteSyntaxHelpers(array)
  implicit final def costanzaOps(jerry: String) = new JerryStringer(jerry)
  implicit final def taggedByteOps[A: ByteEV](repr: A) = new TaggedByteSyntax[A](repr)
  implicit final def taggedStringOps[A: StringEV](repr: A) = new TaggedStringSyntax[A](repr)

}
