package tsec.jws

import io.circe.{DecodingFailure, Error}
import org.apache.commons.codec.binary.Base64
import tsec.common.NonFatal

trait JWSSerializer[A] {
  def serializeToUtf8(body: A): Array[Byte]
  def fromUtf8Bytes(array: Array[Byte]): Either[Error, A]
  def toB64URL(elem: A): String = Base64.encodeBase64URLSafeString(serializeToUtf8(elem))
  def fromB64URL(encoded: String): Either[Error, A] =
    try {
      fromUtf8Bytes(Base64.decodeBase64(encoded))
    } catch {
      case t: Throwable if NonFatal(t) =>
        Left(DecodingFailure("Invalid encoding", Nil))
    }
}
