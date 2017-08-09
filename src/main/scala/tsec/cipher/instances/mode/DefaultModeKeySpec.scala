package tsec.cipher.instances.mode

import javax.crypto.spec.IvParameterSpec

import tsec.cipher.instances._

trait DefaultModeKeySpec[T] {
  implicit val spec = new ModeKeySpec[T]{
    def buildAlgorithmSpec(specBytes: Array[Byte]): JSpec[T] = tagSpec[T](new IvParameterSpec(specBytes))
  }
}
