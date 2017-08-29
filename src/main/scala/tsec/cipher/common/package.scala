package tsec.cipher

import java.security.spec.AlgorithmParameterSpec

import com.softwaremill.tagging._
import tsec.core.CryptoTag

package object common {
  /*
  Todo: Evaluate necessity for parameters in plaintext?
  Ciphertext makes sense. Not so much in the plaintext.
   */
  case class PlainText[A, M, P](content: Array[Byte])
  case class CipherText[A, M, P](content: Array[Byte], iv: Array[Byte])
  case class AAD(aad: Array[Byte]) extends AnyVal

  type JSpec[T] = AlgorithmParameterSpec @@ T
  def tagSpec[T](a: AlgorithmParameterSpec): JSpec[T] = a.taggedWith[T]

  sealed trait CipherPadding
  type Padding[T] = CryptoTag[T] @@ CipherPadding
}
