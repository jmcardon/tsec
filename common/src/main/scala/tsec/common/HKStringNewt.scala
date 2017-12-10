package tsec.common

private[tsec] trait HKStringNewt {

  type Repr[A] <: String

  def is[A]: cats.evidence.Is[String, Repr[A]]
}
