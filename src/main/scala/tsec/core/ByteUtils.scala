package tsec.core

import shapeless.{Generic, HNil, ::}

object ByteUtils {

  type ByteAux[A] = Generic[A] {
    type Repr = Array[Byte] :: HNil
  }

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
}
