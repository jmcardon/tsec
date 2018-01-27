package tsec.common

private[tsec] trait HK2ByteNewt {
  type Repr[A, B] <: Array[Byte]

  def is[A, B]: cats.evidence.Is[Array[Byte], Repr[A, B]]
}
