package tsec.common

/** A higher kinded existential newt that the
  * compiler can wrap without boxing.
  */
@deprecated(
  "methods over cats.evidence.Is have more " +
  "cast overhead than manually written newtypes. " +
  "For performance's sake, these types are " +
  "deprecated and will be removed",
  "0.0.1-M10"
)
private[tsec] trait HKByteNewt {

  type Repr[A] <: Array[Byte]

  def is[A]: cats.evidence.Is[Array[Byte], Repr[A]]
}
