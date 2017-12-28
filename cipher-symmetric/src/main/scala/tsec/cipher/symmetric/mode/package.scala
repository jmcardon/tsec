package tsec.cipher.symmetric

import java.security.spec.AlgorithmParameterSpec

import cats.evidence.Is
import tsec.common.{CryptoTag, ManagedRandom}
import javax.crypto.spec.IvParameterSpec

package object mode {
  sealed trait TaggedParameterSpec {
    type I
    val is: Is[I, AlgorithmParameterSpec]
  }

  protected val TaggedParameterSpec$$ : TaggedParameterSpec = new TaggedParameterSpec {
    type I = AlgorithmParameterSpec
    val is = Is.refl[AlgorithmParameterSpec]
  }

  type ParameterSpec[A] = TaggedParameterSpec$$.I

  object ParameterSpec {
    @inline def fromSpec[A: CipherMode](spec: AlgorithmParameterSpec): ParameterSpec[A] =
      TaggedParameterSpec$$.is.flip.coerce(spec)
    @inline def toRepr[A](spec: ParameterSpec[A]): AlgorithmParameterSpec = TaggedParameterSpec$$.is.coerce(spec)
  }

  /**
    * This trait propagates type information about a parametrized T being a symmetric cipher mode of operation
    * @tparam T
    */
  trait CipherMode[T] extends CryptoTag[T] {
    val ivLength: Int
    def buildIvFromBytes(specBytes: Array[Byte]): ParameterSpec[T]
    def genIv: ParameterSpec[T]
  }

  /** Same as above, but for AEAD
    *
    * @tparam T
    */
  trait AEADMode[T] extends CipherMode[T]

  abstract class DefaultModeKeySpec[T](repr: String, ivLen: Int) extends ManagedRandom {
    implicit val spec = new CipherMode[T] { self =>

      val ivLength: Int = ivLen

      override lazy val algorithm: String = repr

      def buildIvFromBytes(specBytes: Array[Byte]): ParameterSpec[T] =
        ParameterSpec.fromSpec[T](new IvParameterSpec(specBytes))(self)

      def genIv: ParameterSpec[T] = {
        val byteArray = new Array[Byte](ivLen)
        nextBytes(byteArray)
        ParameterSpec.fromSpec[T](new IvParameterSpec(byteArray))(self)
      }
    }
  }
}
