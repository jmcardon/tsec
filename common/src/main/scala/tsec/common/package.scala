package tsec

import java.nio.charset.StandardCharsets
import java.util.Base64
import org.apache.commons.codec.binary.{Base64 => AB64}

import cats.effect.Sync
import org.apache.commons.codec.binary.Hex
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
    def asByteArray(implicit byteEV: ByteEV[A]): Array[Byte] = byteEV.toArray(repr)
  }

  class TaggedStringSyntax[A](val repr: A) extends AnyVal {
    def asString(implicit stringEV: StringEV[A]): String = stringEV.asString(repr)
  }

  final class JerryStringer(val s: String) extends AnyVal {
    def utf8Bytes: Array[Byte]                              = s.getBytes(StandardCharsets.UTF_8)
    def asciiBytes: Array[Byte]                             = s.getBytes(StandardCharsets.US_ASCII)
    def base64Bytes: Array[Byte]                            = Base64.getDecoder.decode(s)
    def base64UrlBytes: Array[Byte]                         = AB64.decodeBase64(s)
    def hexBytes[F[_]](implicit F: Sync[F]): F[Array[Byte]] = F.delay(Hex.decodeHex(s))
    def hexBytesUnsafe: Array[Byte]                         = Hex.decodeHex(s)
    def toStringRepr[A](implicit stringEV: StringEV[A]): A  = stringEV.fromString(s)
  }

  final class ByteSyntaxHelpers(val array: Array[Byte]) extends AnyVal {
    def toUtf8String                             = new String(array, StandardCharsets.UTF_8)
    def toAsciiString                            = new String(array, StandardCharsets.US_ASCII)
    def toB64UrlString: String                   = AB64.encodeBase64URLSafeString(array)
    def toB64String: String                      = Base64.getEncoder.encodeToString(array)
    def toHexString: String                      = Hex.encodeHexString(array)
    def toRepr[A](implicit byteEV: ByteEV[A]): A = byteEV.fromArray(array)
  }

  implicit final def byteSyntaxOps(array: Array[Byte])     = new ByteSyntaxHelpers(array)
  implicit final def costanzaOps(jerry: String)            = new JerryStringer(jerry)
  implicit final def taggedByteOps[A: ByteEV](repr: A)     = new TaggedByteSyntax[A](repr)
  implicit final def taggedStringOps[A: StringEV](repr: A) = new TaggedStringSyntax[A](repr)

  protected[tsec] val SecureRandomId$$ : TaggedString = new TaggedString {
    type I = String
    val is: Is[I, String] = Is.refl[I]
  }

  type SecureRandomId = SecureRandomId$$.I

}
