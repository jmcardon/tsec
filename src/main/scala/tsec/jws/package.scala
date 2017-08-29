package tsec

import java.nio.charset.StandardCharsets
import java.util.Base64

package object jws {

  implicit class JerryStringer(val s: String) extends AnyVal {
    def utf8Bytes: Array[Byte]  = s.getBytes(StandardCharsets.UTF_8)
    def asciiBytes: Array[Byte] = s.getBytes(StandardCharsets.US_ASCII)
    def base64Bytes: Array[Byte] = Base64.getDecoder.decode(s)
  }

  implicit class BytesToStr(val s: Array[Byte]) extends AnyVal {
    def toUtf8String  = new String(s, StandardCharsets.UTF_8)
    def toAsciiString = new String(s, StandardCharsets.US_ASCII)
    def toB64UrlString: String = Base64.getUrlEncoder.encodeToString(s)
    def toB64String: String = Base64.getEncoder.encodeToString(s)
  }
}
