package tsec.common

/** A higher kinded existential newt that the
  * compiler can wrap without boxing.
  */
private[tsec] trait HKByteNewt {

  type Repr[A] <: Array[Byte]

  def is[A]: cats.evidence.Is[Array[Byte], Repr[A]]
}
