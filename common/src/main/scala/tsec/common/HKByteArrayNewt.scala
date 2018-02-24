package tsec.common

import cats.evidence.Is

/** Parametrically polymorphic existential over byte arrays (to avoid boxing)
  *
  */
@deprecated(
  "methods over cats.evidence.Is have more " +
  "cast overhead than manually written newtypes. " +
  "For performance's sake, these types are " +
  "deprecated and will be removed",
  "0.0.1-M10"
)
private[tsec] trait HKByteArrayNewt {
  type Repr[A] <: Array[Byte]
  def is[G]: Is[Array[Byte], Repr[G]]
}
