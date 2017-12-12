package tsec.common

import java.security.MessageDigest

object ByteUtils {

  @inline def zeroByteArray(a: Array[Byte]): Unit = {
    java.util.Arrays.fill(a, 0.toByte)
  }

  @inline def zeroCharArray(a: Array[Char]): Unit = {
    java.util.Arrays.fill(a, 0.toChar)
  }

  @inline def constantTimeEquals(a: Array[Byte], b: Array[Byte]): Boolean =
    MessageDigest.isEqual(a, b)

}
