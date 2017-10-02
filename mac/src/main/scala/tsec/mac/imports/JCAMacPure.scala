package tsec.mac.imports

import cats.effect.IO
import tsec.common.ByteUtils.ByteAux
import tsec.mac.core.MacPrograms

class JCAMacPure[A: ByteAux: MacTag](algebra: JMacPureInterpreter[A])
    extends MacPrograms[IO, A, MacSigningKey](algebra) {}

object JCAMacPure {
  def apply[A: ByteAux: MacTag](implicit alg: JMacPureInterpreter[A]) =
    new JCAMacPure[A](alg)

  implicit def generate[A: ByteAux: MacTag](implicit alg: JMacPureInterpreter[A]): JCAMacPure[A] =
    apply[A]
}
