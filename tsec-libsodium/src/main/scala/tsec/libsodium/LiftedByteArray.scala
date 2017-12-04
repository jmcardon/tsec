package tsec.libsodium

import cats.evidence.Is

/** Parametrically polymorphic existential over crypto keys
  *
  */
private[tsec] trait LiftedByteArray {
  type AuthRepr[A] <: Array[Byte]
  def is[G]: Is[Array[Byte], AuthRepr[G]]
}
