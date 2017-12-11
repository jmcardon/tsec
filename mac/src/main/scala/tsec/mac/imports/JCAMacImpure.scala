package tsec.mac.imports

import cats.instances.either._
import tsec.mac.core.{MAC, MacPrograms, MacTag}

sealed class JCAMacImpure[A: MacTag](
    algebra: JMacInterpreter[A]
) extends MacPrograms[MacErrorM, A, MacSigningKey](algebra)

object JCAMacImpure {
  def apply[A: MacTag]: JCAMacImpure[A]                = new JCAMacImpure[A](new JMacInterpreter[A]) {}
  implicit def getInstance[A: MacTag]: JCAMacImpure[A] = new JCAMacImpure[A](new JMacInterpreter[A]) {}

  def sign[A: MacTag](content: Array[Byte], key: MacSigningKey[A])(
      implicit jc: JCAMacImpure[A]
  ): MacErrorM[MAC[A]] = jc.sign(content, key)

  def verify[A: MacTag](toSign: Array[Byte], signed: MAC[A], key: MacSigningKey[A])(
      implicit jc: JCAMacImpure[A]
  ): MacErrorM[Boolean] = jc.verify(toSign, signed, key)

  def verifyArrays[A: MacTag](toSign: Array[Byte], signed: Array[Byte], key: MacSigningKey[A])(
      implicit jc: JCAMacImpure[A]
  ): MacErrorM[Boolean] = jc.verifyArrays(toSign, signed, key)
}
