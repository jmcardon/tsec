package tsec.mac.instance.threadlocal

import cats.effect.IO
import tsec.mac.MacKey
import tsec.mac.core.MacPrograms
import tsec.mac.core.MacPrograms.MacAux
import tsec.mac.instance.MacTag

sealed abstract class JCATLMacPure[A: MacTag: MacAux](algebra: JMacPureI[A]) extends MacPrograms[IO, A, MacKey](algebra)

object JCATLMacPure {
  def apply[A: MacTag: MacAux](queueSize: Int = 5) = new JCATLMacPure[A](JMacPureI(queueSize)) {}

  implicit def getJMac[A: MacTag: MacAux]: JCATLMacPure[A] = new JCATLMacPure[A](JMacPureI()) {}
}
