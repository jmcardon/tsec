package tsec.cipher.symmetric

import java.security.spec.AlgorithmParameterSpec
import cats.evidence.Is
import tsec.common.CryptoTag
import java.security.SecureRandom
import java.util.concurrent.atomic.LongAdder
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

  abstract class DefaultModeKeySpec[T](repr: String, ivLen: Int) {
    implicit val spec = new CipherMode[T] { self =>

      val ivLength: Int = ivLen

      /** Cache our random, and seed it properly as per
        * https://tersesystems.com/2015/12/17/the-right-way-to-use-securerandom/
        */
      private val cachedRand: SecureRandom = {
        val r = new SecureRandom()
        r.nextBytes(new Array[Byte](20))
        r
      }

      /** We will keep a reference to how many times our random is utilized
        * After a sensible Integer.MaxValue/2 times, we should reseed
        */
      private val adder: LongAdder = new LongAdder
      private val MaxBeforeReseed  = (Integer.MAX_VALUE / 2).toLong

      private def reSeed(): Unit = {
        adder.reset()
        cachedRand.nextBytes(new Array[Byte](20))
      }

      override lazy val algorithm: String = repr

      def buildIvFromBytes(specBytes: Array[Byte]): ParameterSpec[T] =
        ParameterSpec.fromSpec[T](new IvParameterSpec(specBytes))(self)

      def genIv: ParameterSpec[T] = {
        adder.increment()
        if (adder.sum() >= MaxBeforeReseed)
          reSeed()

        val byteArray = new Array[Byte](ivLen)
        cachedRand.nextBytes(byteArray)
        ParameterSpec.fromSpec[T](new IvParameterSpec(byteArray))(self)
      }
    }
  }
}
