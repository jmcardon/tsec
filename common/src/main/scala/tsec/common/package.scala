package tsec

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.util.Base64

import org.apache.commons.codec.binary.{Base64 => AB64}
import cats.effect.Sync
import org.apache.commons.codec.binary.Hex
import cats.evidence.Is

import scala.util.control.NoStackTrace

package object common {

  trait TSecError extends NoStackTrace {
    def cause: String
    override def getMessage: String = cause
  }

  trait StringNewt {
    type I <: String

    val is: Is[I, String]
  }

  sealed trait TSecPrimitiveEncoder[T] {
    def encode(v: T): Array[Byte]
  }

  // ByteBuffer capacity based on https://docs.oracle.com/javase/tutorial/java/nutsandbolts/datatypes.html
  implicit val intPrimitiveEncoder: TSecPrimitiveEncoder[Int] = new TSecPrimitiveEncoder[Int] {
    def encode(v: Int) = ByteBuffer.allocate(4).putInt(v).array()
  }

  implicit val longPrimitiveEncoder: TSecPrimitiveEncoder[Long] = new TSecPrimitiveEncoder[Long] {
    def encode(v: Long) = ByteBuffer.allocate(8).putLong(v).array()
  }

  implicit val shortPrimitiveEncoder: TSecPrimitiveEncoder[Short] = new TSecPrimitiveEncoder[Short] {
    def encode(v: Short) = ByteBuffer.allocate(4).putShort(v).array()
  }

  implicit val floatPrimitiveEncoder: TSecPrimitiveEncoder[Float] = new TSecPrimitiveEncoder[Float] {
    def encode(v: Float) = ByteBuffer.allocate(4).putFloat(v).array()
  }

  implicit val doublePrimitiveEncoder: TSecPrimitiveEncoder[Double] = new TSecPrimitiveEncoder[Double] {
    def encode(v: Double) = ByteBuffer.allocate(8).putDouble(v).array()
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

    def toFloatUnsafe: Float   = ByteBuffer.wrap(array).getFloat
    def toDoubleUnsafe: Double = ByteBuffer.wrap(array).getDouble
    def toLongUnsafe: Long     = ByteBuffer.wrap(array).getLong
    def toShortUnsafe: Short   = ByteBuffer.wrap(array).getShort
    def toIntUnsafe: Int       = ByteBuffer.wrap(array).getInt

    def toFloat[F[_]](implicit F: Sync[F]): F[Float]   = F.delay(toFloatUnsafe)
    def toDouble[F[_]](implicit F: Sync[F]): F[Double] = F.delay(toDoubleUnsafe)
    def toLong[F[_]](implicit F: Sync[F]): F[Long]     = F.delay(toLongUnsafe)
    def toShort[F[_]](implicit F: Sync[F]): F[Short]   = F.delay(toShortUnsafe)
    def toInt[F[_]](implicit F: Sync[F]): F[Int]       = F.delay(toIntUnsafe)

  }

  implicit final def byteSyntaxOps(array: Array[Byte]) = new ByteSyntaxHelpers(array)
  implicit final def costanzaOps(jerry: String)        = new JerryStringer(jerry)

  implicit final class primitiveEncoderOps[T](v: T)(implicit E: TSecPrimitiveEncoder[T]) {
    def toBytes: Array[Byte] = E.encode(v)
  }

  protected[tsec] val SecureRandomId$$ : StringNewt = new StringNewt {
    type I = String
    val is: Is[I, String] = Is.refl[I]
  }

  type SecureRandomId = SecureRandomId$$.I

}
