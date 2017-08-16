package tsec.cipher

import java.security.spec.AlgorithmParameterSpec

import com.softwaremill.tagging._
import tsec.core.CryptoTag

package object common {
  case class PlainText[A, M, P](content: Array[Byte])
  case class CipherText[A, M, P](content: Array[Byte], iv: Array[Byte])
  case class AAD(aad: Array[Byte]) extends AnyVal

  type JSpec[T] = AlgorithmParameterSpec @@ T
  def tagSpec[T](a: AlgorithmParameterSpec): JSpec[T] = a.taggedWith[T]

  case object NoSuchInstanceError
  type NoSuchInstanceError = NoSuchInstanceError.type

  sealed trait CipherPadding
  type Padding[T] = CryptoTag[T] @@ CipherPadding
}
