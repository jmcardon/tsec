package tsec.mac.instance.threadlocal

import cats.effect.IO
import tsec.core.ByteUtils.ByteAux
import tsec.mac.core.MacPrograms
import tsec.mac.instance.{MacSigningKey, MacTag}

sealed abstract class JCATLMacPure[A: MacTag: ByteAux](algebra: JMacPureI[A])
    extends MacPrograms[IO, A, MacSigningKey](algebra)

object JCATLMacPure {
  def apply[A: MacTag: ByteAux](queueSize: Int = 5) = new JCATLMacPure[A](JMacPureI(queueSize)) {}

  implicit def getJMac[A: MacTag: ByteAux]: JCATLMacPure[A] = new JCATLMacPure[A](JMacPureI()) {}
}
