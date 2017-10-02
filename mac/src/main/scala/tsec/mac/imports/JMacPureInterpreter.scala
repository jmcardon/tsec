package tsec.mac.imports

import javax.crypto.Mac

import cats.effect.IO
import tsec.common.ByteUtils.ByteAux
import tsec.mac.core.MacAlgebra

sealed protected[tsec] abstract class JMacPureInterpreter[A: ByteAux](implicit macTag: MacTag[A])
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

object JMacPureInterpreter {
  def apply[A: ByteAux: MacTag] = new JMacPureInterpreter[A] {}

  implicit def gen[A: ByteAux: MacTag]: JMacPureInterpreter[A] = apply[A]
}
