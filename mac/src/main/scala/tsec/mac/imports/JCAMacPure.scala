package tsec.mac.imports

import cats.effect.{IO, Sync}
import tsec.mac.core.{MAC, MacPrograms, MacTag}

class JCAMacPure[F[_]: Sync, A: MacTag](algebra: JMacPureInterpreter[F, A])
    extends MacPrograms[F, A, MacSigningKey](algebra) {}

object JCAMacPure {
  def apply[F[_]: Sync, A: MacTag](implicit alg: JMacPureInterpreter[F, A]) =
    new JCAMacPure[F, A](alg)

  implicit def generate[F[_]: Sync, A: MacTag](implicit alg: JMacPureInterpreter[F, A]): JCAMacPure[F, A] =
    apply[F, A]

  def sign[F[_]: Sync, A: MacTag](content: Array[Byte], key: MacSigningKey[A])(
      implicit jc: JCAMacPure[F, A]
  ): F[MAC[A]] = jc.sign(content, key)

  def verify[F[_]: Sync, A: MacTag](toSign: Array[Byte], signed: MAC[A], key: MacSigningKey[A])(
      implicit jc: JCAMacPure[F, A]
  ): F[Boolean] = jc.verify(toSign, signed, key)

  def verifyArrays[F[_]: Sync, A: MacTag](toSign: Array[Byte], signed: Array[Byte], key: MacSigningKey[A])(
      implicit jc: JCAMacPure[F, A]
  ): F[Boolean] = jc.verifyArrays(toSign, signed, key)
}
