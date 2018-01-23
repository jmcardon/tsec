package tsec.common

import java.security.MessageDigest

object ByteUtils {

  @inline def zeroByteArray(a: Array[Byte]): Unit =
    java.util.Arrays.fill(a, 0.toByte)

  @inline def zeroCharArray(a: Array[Char]): Unit =
    java.util.Arrays.fill(a, 0.toChar)

  @inline def constantTimeEquals(a: Array[Byte], b: Array[Byte]): Boolean =
    MessageDigest.isEqual(a, b)

  @inline def intToBytes(a: Int): Array[Byte] =
    Array(
      (a >> 24).toByte,
      (a >> 16).toByte,
      (a >> 8).toByte,
      a.toByte
    )

  @inline def unsafeBytesToInt(a: Array[Byte]): Int =
    a(0) << 24 | (a(1) & 0xFF) << 16 | (a(2) & 0xFF) << 8 | (a(3) & 0xFF)

  @inline def bytesToInt(a: Array[Byte]): Option[Int] =
    if (a.length != Integer.BYTES) None
    else Some(unsafeBytesToInt(a))

  @inline def longToBytes(x: Long): Array[Byte] =
    Array[Byte](
      (x >> 56).toByte,
      (x >> 48).toByte,
      (x >> 40).toByte,
      (x >> 32).toByte,
      (x >> 24).toByte,
      (x >> 16).toByte,
      (x >> 8).toByte,
      x.toByte
    )

  @inline def unsafeBytesToLong(a: Array[Byte]): Long =
    (a(0).toLong << 56) |
      ((a(1).toLong & 0xff) << 48) |
      ((a(2).toLong & 0xff) << 40) |
      ((a(3).toLong & 0xff) << 32) |
      ((a(4).toLong & 0xff) << 24) |
      ((a(5).toLong & 0xff) << 16) |
      ((a(6).toLong & 0xff) << 8) |
      a(7).toLong & 0xff

  @inline def bytesToLong(a: Array[Byte]): Option[Long] =
    if (a.length != java.lang.Long.BYTES) None
    else Some(unsafeBytesToLong(a))

}
