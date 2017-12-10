package tsec.mac.imports.threadlocal

import cats.effect.IO
import tsec.mac.core.{MacPrograms, MacTag}
import tsec.mac.imports.MacSigningKey

sealed abstract class JCATLMacPure[A: MacTag](algebra: JMacPureI[A])
    extends MacPrograms[IO, A, MacSigningKey](algebra)

object JCATLMacPure {
  def apply[A: MacTag](queueSize: Int = 5) = new JCATLMacPure[A](JMacPureI(queueSize)) {}

  implicit def getJMac[A: MacTag]: JCATLMacPure[A] = new JCATLMacPure[A](JMacPureI()) {}
}
