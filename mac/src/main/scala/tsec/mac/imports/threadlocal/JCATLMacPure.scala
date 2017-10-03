package tsec.mac.imports.threadlocal

import cats.effect.IO
import tsec.common.ByteEV
import tsec.mac.core.MacPrograms
import tsec.mac.imports.{MacSigningKey, MacTag}

sealed abstract class JCATLMacPure[A: MacTag: ByteEV](algebra: JMacPureI[A])
    extends MacPrograms[IO, A, MacSigningKey](algebra)

object JCATLMacPure {
  def apply[A: MacTag: ByteEV](queueSize: Int = 5) = new JCATLMacPure[A](JMacPureI(queueSize)) {}

  implicit def getJMac[A: MacTag: ByteEV]: JCATLMacPure[A] = new JCATLMacPure[A](JMacPureI()) {}
}
