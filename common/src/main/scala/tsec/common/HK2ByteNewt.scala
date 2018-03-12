package tsec.common

@deprecated(
  "methods over cats.evidence.Is have more " +
  "cast overhead than manually written newtypes. " +
  "For performance's sake, these types are " +
  "deprecated and will be removed",
  "0.0.1-M10"
)
private[tsec] trait HK2ByteNewt {
  type Repr[A, B] <: Array[Byte]

  def is[A, B]: cats.evidence.Is[Array[Byte], Repr[A, B]]
}
