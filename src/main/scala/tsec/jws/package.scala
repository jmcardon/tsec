package tsec

import java.nio.charset.StandardCharsets

package object jws {
  val AsciiDot: Byte = 0x2E.toByte
  implicit class JerryStringer(val s: String) extends AnyVal {
    def utf8Bytes: Array[Byte]  = s.getBytes(StandardCharsets.UTF_8)
    def asciiBytes: Array[Byte] = s.getBytes(StandardCharsets.US_ASCII)
  }

  implicit class BytesToStr(val s: Array[Byte]) extends AnyVal {
    def toUtf8String  = new String(s, StandardCharsets.UTF_8)
    def toAsciiString = new String(s, StandardCharsets.US_ASCII)
  }
}
