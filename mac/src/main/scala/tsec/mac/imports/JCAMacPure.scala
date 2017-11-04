package tsec.mac.imports

import cats.effect.{IO, Sync}
import tsec.common.ByteEV
import tsec.mac.core.MacPrograms

class JCAMacPure[F[_]: Sync, A: ByteEV: MacTag](algebra: JMacPureInterpreter[F, A])
    extends MacPrograms[F, A, MacSigningKey](algebra) {}

object JCAMacPure {
  def apply[F[_]: Sync, A: ByteEV: MacTag](implicit alg: JMacPureInterpreter[F, A]) =
    new JCAMacPure[F, A](alg)

  implicit def generate[F[_]: Sync, A: ByteEV: MacTag](implicit alg: JMacPureInterpreter[F, A]): JCAMacPure[F, A] =
    apply[F, A]
}
