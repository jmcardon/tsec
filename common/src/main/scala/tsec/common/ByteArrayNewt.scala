package tsec.common

import cats.evidence.Is

@deprecated(
  "methods over cats.evidence.Is have more " +
  "cast overhead than manually written newtypes. " +
  "For performance's sake, these types are " +
  "deprecated and will be removed",
  "0.0.1-M10"
)
trait ByteArrayNewt {
  type I <: Array[Byte]

  val is: Is[I, Array[Byte]]
}
