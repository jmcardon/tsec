package tsec.common

import cats.evidence.Is

/** Parametrically polymorphic existential over crypto keys
  *
  */
private[tsec] trait HKStringNewt {
  type Repr[A] <: String
  def is[G]: Is[String, Repr[G]]
}
