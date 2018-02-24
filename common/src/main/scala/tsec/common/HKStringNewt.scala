package tsec.common

import cats.evidence.Is

/** Parametrically polymorphic existential over crypto keys
  *
  */
@deprecated(
  "methods over cats.evidence.Is have more " +
  "cast overhead than manually written newtypes. " +
  "For performance's sake, these types are " +
  "deprecated and will be removed",
  "0.0.1-M10"
)
private[tsec] trait HKStringNewt {
  type Repr[A] <: String
  def is[G]: Is[String, Repr[G]]

}
