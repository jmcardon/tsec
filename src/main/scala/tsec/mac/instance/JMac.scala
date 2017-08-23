package tsec.mac.instance

import cats.effect.IO
import shapeless.{::, HNil}
import tsec.mac.MacKey
import tsec.mac.core.MacPrograms
import tsec.mac.core.MacPrograms.MacAux

sealed abstract class JMac[A: MacTag: MacAux](algebra: JMacPureI[A]) extends MacPrograms[IO, A, MacKey](algebra)

object JMac {
  def apply[A: MacTag: MacAux](queueSize: Int = 5) = new JMac[A](JMacPureI(queueSize)) {}

  implicit def getJMac[A: MacTag: MacAux]: JMac[A] = new JMac[A](JMacPureI()) {}
}
