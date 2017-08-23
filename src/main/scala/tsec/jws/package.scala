package tsec

import java.nio.charset.StandardCharsets

import org.apache.commons.codec.binary.Base64

package object jws {
  val AsciiDot: Byte = 0x2E.toByte
  implicit class JerryStringer(val s: String) extends AnyVal {
    def utf8Bytes: Array[Byte]  = s.getBytes(StandardCharsets.UTF_8)
    def asciiBytes: Array[Byte] = s.getBytes(StandardCharsets.US_ASCII)
    def base64Bytes: Array[Byte] = Base64.decodeBase64(s)
  }

  implicit class BytesToStr(val s: Array[Byte]) extends AnyVal {
    def toUtf8String  = new String(s, StandardCharsets.UTF_8)
    def toAsciiString = new String(s, StandardCharsets.US_ASCII)
    def toB64UrlString: String = Base64.encodeBase64URLSafeString(s)
  }
}
