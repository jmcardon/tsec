package tsec.cipher.instances

import tsec.core.CryptoTag

trait ModeKeySpec[T] extends CryptoTag[T] {
  def buildAlgorithmSpec(specBytes: Array[Byte]): JSpec[T]
}
