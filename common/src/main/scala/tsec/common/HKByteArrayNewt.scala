package tsec.common

import cats.evidence.Is

/** Parametrically polymorphic existential over byte arrays (to avoid boxing)
  *
  */
private[tsec] trait HKByteArrayNewt {
  type Repr[A] <: Array[Byte]
  def is[G]: Is[Array[Byte], Repr[G]]
}
