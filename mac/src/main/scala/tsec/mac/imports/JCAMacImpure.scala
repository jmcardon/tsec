package tsec.mac.imports

import cats.implicits._
import tsec.common._
import tsec.mac.core.MacPrograms

sealed class JCAMacImpure[A: MacTag: ByteEV](
    algebra: JMacInterpreter[A]
) extends MacPrograms[MacErrorM, A, MacSigningKey](algebra)

object JCAMacImpure {
  def apply[A: MacTag: ByteEV]: JCAMacImpure[A] = new JCAMacImpure[A](new JMacInterpreter[A]) {}
  implicit def getInstance[A: MacTag: ByteEV]   = new JCAMacImpure[A](new JMacInterpreter[A]) {}
}
