package tsec.common

import java.security.MessageDigest

object ByteUtils {
  def constantTimeEquals(a: Array[Byte], b: Array[Byte]): Boolean =
    MessageDigest.isEqual(a, b)

}
