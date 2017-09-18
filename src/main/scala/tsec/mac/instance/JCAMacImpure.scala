package tsec.mac.instance

import cats.implicits._
import tsec.core.ByteUtils.ByteAux
import tsec.mac.core.MacPrograms

sealed class JCAMacImpure[A: MacTag: ByteAux](
    algebra: JMacInterpreter[A]
) extends MacPrograms[Either[MacError, ?], A, MacSigningKey](algebra)

object JCAMacImpure {
  def apply[A: MacTag: ByteAux]: JCAMacImpure[A] = new JCAMacImpure[A](new JMacInterpreter[A]) {}
  implicit def getInstance[A: MacTag: ByteAux]   = new JCAMacImpure[A](new JMacInterpreter[A]) {}
}
