package tsec.core

object ByteUtils {

  def constantTimeEquals(a: Array[Byte], b: Array[Byte]): Boolean =
    if (a.length != b.length) false
    else {
      var nonEqual = 0
      var i        = 0
      while (i != a.length) {
        nonEqual |= (a(i) ^ b(i))
        i += 1
      }
      nonEqual == 0
    }

  def arraysEqual2(a: Array[Byte], b: Array[Byte]): Boolean =
    if (a.length != b.length) false
    else {
      var nonEqual = 0
      var i        = 0
      while (i != a.length) {
        nonEqual |= (a(i) ^ b(i))
        if(nonEqual != 0)
          return false

        i += 1
      }
      true
    }
}
