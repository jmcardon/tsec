package tsec.mac.instance.threadlocal

import javax.crypto.Mac

import cats.effect.IO
import tsec.core.QueueAlloc
import tsec.mac.MacKey
import tsec.mac.core.{MacAlgebra, MacSigningKey}
import tsec.mac.instance.MacTag

sealed abstract class JMacPureI[A](tl: QueueAlloc[Mac])(implicit macTag: MacTag[A]) extends MacAlgebra[IO, A, MacKey] {
  type M = Mac

  def genInstance: IO[Mac] =
    IO({
      val inst = tl.dequeue
      if (inst != null)
        inst
      else
        Mac.getInstance(macTag.algorithm)
    })

  def sign(content: Array[Byte], key: MacSigningKey[MacKey[A]]): IO[Array[Byte]] =
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
