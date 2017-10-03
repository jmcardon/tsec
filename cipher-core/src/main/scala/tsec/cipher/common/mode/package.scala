package tsec.cipher.common

import java.security.spec.AlgorithmParameterSpec

import cats.evidence.Is
import tsec.common.CryptoTag

package object mode {
  sealed trait TaggedParameterSpec {
    type I
    val is: Is[I, AlgorithmParameterSpec]
  }

  protected val TaggedParameterSpec$$: TaggedParameterSpec = new TaggedParameterSpec {
    type I = AlgorithmParameterSpec
    val is = Is.refl[AlgorithmParameterSpec]
  }

  type ParameterSpec[A] = TaggedParameterSpec$$.I

  object ParameterSpec {
    @inline def fromSpec[A: ModeKeySpec](spec: AlgorithmParameterSpec): ParameterSpec[A] = TaggedParameterSpec$$.is.flip.coerce(spec)
    @inline def toRepr[A](spec: ParameterSpec[A]): AlgorithmParameterSpec = TaggedParameterSpec$$.is.coerce(spec)
  }

  trait ModeKeySpec[T] extends CryptoTag[T] {
    val ivLength: Int
    def buildIvFromBytes(specBytes: Array[Byte]): ParameterSpec[T]
    def genIv: ParameterSpec[T]
  }
}
