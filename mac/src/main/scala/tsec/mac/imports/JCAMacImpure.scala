package tsec.mac.imports

import cats.implicits._
import tsec.common._
import tsec.mac.core.{MacPrograms, MacTag}

sealed class JCAMacImpure[A: MacTag](
    algebra: JMacInterpreter[A]
) extends MacPrograms[MacErrorM, A, MacSigningKey](algebra)

object JCAMacImpure {
  def apply[A: MacTag]: JCAMacImpure[A] = new JCAMacImpure[A](new JMacInterpreter[A]) {}
  implicit def getInstance[A: MacTag]   = new JCAMacImpure[A](new JMacInterpreter[A]) {}
}
