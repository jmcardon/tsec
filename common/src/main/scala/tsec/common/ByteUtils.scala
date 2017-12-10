package tsec.common

import java.security.MessageDigest

object ByteUtils {
  private val zeroByte = 0.toByte
  private val zeroChar = 0.toChar

  def zeroByteArray(a: Array[Byte]): Unit = {
    var i = 0
    while (i < a.length) {
      a(i) = zeroByte
      i += 1
    }
  }

  def zeroCharArray(a: Array[Char]): Unit = {
    var i = 0
    while (i < a.length) {
      a(i) = zeroChar
      i += 1
    }
  }

  def constantTimeEquals(a: Array[Byte], b: Array[Byte]): Boolean =
    MessageDigest.isEqual(a, b)

}
