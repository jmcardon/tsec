package tsec.mac.imports.threadlocal

import javax.crypto.Mac
import cats.effect.IO
import tsec.common.QueueAlloc
import tsec.mac.core.MacAlgebra
import tsec.mac.imports.{MacSigningKey, MacTag}

sealed abstract class JMacPureI[A](tl: QueueAlloc[Mac])(implicit macTag: MacTag[A])
    extends MacAlgebra[IO, A, MacSigningKey] {
  type M = Mac

  def genInstance: IO[Mac] =
    IO({
      val inst = tl.dequeue
      if (inst != null)
        inst
      else
        Mac.getInstance(macTag.algorithm)
    })

  def sign(content: Array[Byte], key: MacSigningKey[A]): IO[Array[Byte]] =
    for {
      instance <- genInstance
      _        <- IO(instance.init(key.key))
      fin      <- IO(instance.doFinal(content))
      _        <- IO(tl.enqueue(instance))
    } yield fin
}

object JMacPureI {
  def apply[A](numInstances: Int = 5)(implicit macTag: MacTag[A]): JMacPureI[A] = {
    val qA = QueueAlloc(List.fill[Mac](numInstances)(Mac.getInstance(macTag.algorithm)))
    new JMacPureI[A](qA) {}
  }
}
