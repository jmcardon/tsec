package tsec

import java.nio.charset.StandardCharsets
import java.util.Base64
import org.apache.commons.codec.binary.{Base64 => AB64}

import cats.effect.Sync
import org.apache.commons.codec.binary.Hex
import cats.evidence.Is

package object common {

  trait StringNewt {
    type I <: String

    val is: Is[I, String]
  }

  final class JerryStringer(val s: String) extends AnyVal {
    def utf8Bytes: Array[Byte]                              = s.getBytes(StandardCharsets.UTF_8)
    def asciiBytes: Array[Byte]                             = s.getBytes(StandardCharsets.US_ASCII)
    def base64Bytes: Array[Byte]                            = Base64.getDecoder.decode(s)
    def base64UrlBytes: Array[Byte]                         = AB64.decodeBase64(s)
    def hexBytes[F[_]](implicit F: Sync[F]): F[Array[Byte]] = F.delay(Hex.decodeHex(s))
    def hexBytesUnsafe: Array[Byte]                         = Hex.decodeHex(s)
  }

  final class ByteSyntaxHelpers(val array: Array[Byte]) extends AnyVal {
    def toUtf8String           = new String(array, StandardCharsets.UTF_8)
    def toAsciiString          = new String(array, StandardCharsets.US_ASCII)
    def toB64UrlString: String = AB64.encodeBase64URLSafeString(array)
    def toB64String: String    = Base64.getEncoder.encodeToString(array)
    def toHexString: String    = Hex.encodeHexString(array)
  }

  implicit final def byteSyntaxOps(array: Array[Byte]) = new ByteSyntaxHelpers(array)
  implicit final def costanzaOps(jerry: String)        = new JerryStringer(jerry)

  protected[tsec] val SecureRandomId$$ : StringNewt = new StringNewt {
    type I = String
    val is: Is[I, String] = Is.refl[I]
  }

  type SecureRandomId = SecureRandomId$$.I

}
