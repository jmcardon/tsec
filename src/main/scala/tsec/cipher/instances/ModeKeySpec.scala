package tsec.cipher.instances

trait ModeKeySpec[T]{
  def buildAlgorithmSpec(specBytes: Array[Byte]): JSpec[T]
}
