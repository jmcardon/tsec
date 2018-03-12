package tsec.common

/** A higher kinded existential newt without compiler dealiasing.
  */
@deprecated(
  "methods over cats.evidence.Is have more " +
  "cast overhead than manually written newtypes. " +
  "For performance's sake, these types are " +
  "deprecated and will be removed",
  "0.0.1-M10"
)
private[tsec] trait HKByteNewtND {

  type Repr[A]

  def is[A]: cats.evidence.Is[Array[Byte], Repr[A]]
}
