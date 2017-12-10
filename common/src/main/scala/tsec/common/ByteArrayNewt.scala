package tsec.common

import cats.evidence.Is

trait ByteArrayNewt {
  type I <: Array[Byte]

  val is: Is[I, Array[Byte]]
}
