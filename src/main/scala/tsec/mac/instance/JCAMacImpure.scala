package tsec.mac.instance

import cats.implicits._
import tsec.core.ByteUtils.ByteAux
import tsec.mac.MacKey
import tsec.mac.core.MacPrograms

sealed class JCAMacImpure[A: MacTag: ByteAux](
    algebra: JMacInterpreter[A]
) extends MacPrograms[Either[MacError, ?], A, MacKey](algebra)

object JCAMacImpure {
    def getInstance[A: MacTag: ByteAux] = new JCAMacImpure[A](new JMacInterpreter[A]) {}
}