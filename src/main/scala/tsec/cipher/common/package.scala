package tsec.cipher

import java.security.spec.AlgorithmParameterSpec

import shapeless.tag
import shapeless.tag.@@

package object common {

  final case class PlainText(content: Array[Byte]) extends AnyVal
  final case class CipherText[A, M, P](content: Array[Byte], iv: Array[Byte])
  final case class AAD(aad: Array[Byte]) extends AnyVal

  def tagSpec[T](a: AlgorithmParameterSpec): AlgorithmParameterSpec @@ T = tag[T](a)

  type NoSuchInstanceError = NoSuchInstanceError.type

}
