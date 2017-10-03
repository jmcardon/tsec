package tsec.mac.imports

import cats.effect.IO
import tsec.common.ByteEV
import tsec.mac.core.MacPrograms

class JCAMacPure[A: ByteEV: MacTag](algebra: JMacPureInterpreter[A])
    extends MacPrograms[IO, A, MacSigningKey](algebra) {}

object JCAMacPure {
  def apply[A: ByteEV: MacTag](implicit alg: JMacPureInterpreter[A]) =
    new JCAMacPure[A](alg)

  implicit def generate[A: ByteEV: MacTag](implicit alg: JMacPureInterpreter[A]): JCAMacPure[A] =
    apply[A]
}
