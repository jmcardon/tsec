package tsec.core

import java.nio.charset.StandardCharsets
import java.util.Base64

import shapeless.{::, Generic, HNil}

object ByteUtils {

  type ByteAux[A] = Generic[A] {
    type Repr = Array[Byte] :: HNil
  }

  def constantTimeEquals(a: Array[Byte], b: Array[Byte]): Boolean =
    if (a.length != b.length) false
    else {
      var nonEqual = 0
      var i        = 0
      while (i != a.length) {
        nonEqual |= (a(i) ^ b(i))
        i += 1
      }
      nonEqual == 0
    }

  implicit class JerryStringer(val s: String) extends AnyVal {
    def utf8Bytes: Array[Byte]   = s.getBytes(StandardCharsets.UTF_8)
    def asciiBytes: Array[Byte]  = s.getBytes(StandardCharsets.US_ASCII)
    def base64Bytes: Array[Byte] = Base64.getDecoder.decode(s)
  }

  implicit class BytesToStr(val s: Array[Byte]) extends AnyVal {
    def toUtf8String           = new String(s, StandardCharsets.UTF_8)
    def toAsciiString          = new String(s, StandardCharsets.US_ASCII)
    def toB64UrlString: String = Base64.getUrlEncoder.encodeToString(s)
    def toB64String: String    = Base64.getEncoder.encodeToString(s)
  }
}
