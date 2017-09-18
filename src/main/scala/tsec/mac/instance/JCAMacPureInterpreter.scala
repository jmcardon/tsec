package tsec.mac.instance

import javax.crypto.Mac

import cats.effect.IO
import tsec.core.ByteUtils.ByteAux
import tsec.mac.core.MacAlgebra

sealed abstract class JCAMacPureInterpreter[A: ByteAux](implicit macTag: MacTag[A])
    extends MacAlgebra[IO, A, MacSigningKey] {
  type M = Mac

  def genInstance: IO[Mac] = IO(Mac.getInstance(macTag.algorithm))

  def sign(content: Array[Byte], key: MacSigningKey[A]): IO[Array[Byte]] =
    for {
      instance <- genInstance
      _        <- IO(instance.init(key.key))
      result   <- IO(instance.doFinal(content))
    } yield result
}

object JCAMacPureInterpreter {
  def apply[A: ByteAux: MacTag] = new JCAMacPureInterpreter[A] {}

  implicit def gen[A: ByteAux: MacTag]: JCAMacPureInterpreter[A] = apply[A]
}
