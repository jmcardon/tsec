package tsec.mac.instance

import shapeless.{::, HNil}
import tsec.mac.MacKey
import tsec.mac.core.{MacAlgebra, MacPrograms}
import cats.implicits._
import tsec.mac.core.MacPrograms.MacAux

sealed class JMacImpure[A: MacTag: MacAux](
    algebra: JMacInterpreter[A]
) extends MacPrograms[Either[MacError, ?], A, MacKey](algebra)

object JMacImpure {
    def getInstance[A: MacTag: MacAux] = new JMacImpure[A](new JMacInterpreter[A]) {}
}