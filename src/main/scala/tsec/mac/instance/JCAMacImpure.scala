package tsec.mac.instance

import cats.implicits._
import tsec.mac.MacKey
import tsec.mac.core.MacPrograms
import tsec.mac.core.MacPrograms.MacAux

sealed class JCAMacImpure[A: MacTag: MacAux](
    algebra: JMacInterpreter[A]
) extends MacPrograms[Either[MacError, ?], A, MacKey](algebra)

object JCAMacImpure {
    def getInstance[A: MacTag: MacAux] = new JCAMacImpure[A](new JMacInterpreter[A]) {}
}