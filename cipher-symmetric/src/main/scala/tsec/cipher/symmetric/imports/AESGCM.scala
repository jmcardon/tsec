package tsec.cipher.symmetric.imports

import java.util.concurrent.atomic.AtomicInteger

import cats.effect.Sync
import tsec.cipher.common.padding.NoPadding
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.core.{CounterIvStrategy, Iv}
import tsec.cipher.symmetric.imports.primitive.JCAAEADPrimitive

sealed abstract class AESGCMConstruction[A: AES] extends JCAAEAD[A, GCM, NoPadding, GCMCipherText[A]] {

  def genEncryptor[F[_]: Sync]: F[GCMEncryptor[F, A]] = JCAAEADPrimitive[F, A, GCM, NoPadding]()

  /** Our default Iv strategy for GCM mode
    * produces randomized IVs
    *
    *
    * @return
    */
  def defaultIvStrategy: GCMIVStrategy[A] = GCM.randomIVStrategy[A]

  /** An incremental iv strategy, as referenced in the
    * nist recommendations for the GCM mode of operation
    * http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
    * where:
    *
    * The fixed field(nonce) is the leftmost 4 bytes of the IV
    * The invocation field starts as a zeroed out array as the rightmost 8 bytes
    *
    */
  def incrementalIvStrategy: CounterIvStrategy[A, CTR] =
    new CounterIvStrategy[A, CTR] {
      private val delta                      = 1000000
      private val maxVal: Int                = Int.MaxValue - delta
      private val numGen: AtomicInteger      = new AtomicInteger(Int.MinValue)
      private val fixedCounter: Array[Byte]  = Array.fill[Byte](8)(0.toByte)
      private val atomicNonce: AtomicInteger = new AtomicInteger(Int.MinValue)

      def numGenerated[F[_]](implicit F: Sync[F]): F[Long] = F.delay(unsafeNumGenerated)

      def unsafeNumGenerated: Long = numGen.get().toLong

      def genIv[F[_]](implicit F: Sync[F]): F[Iv[A, CTR]] =
        F.delay(genIvUnsafe)

      def genIvUnsafe: Iv[A, CTR] =
        if (numGen.get() >= maxVal)
          throw IvError("Maximum safe nonce number reached")
        else {
          numGen.incrementAndGet()
          val nonce = atomicNonce.incrementAndGet()
          val iv    = new Array[Byte](12) //GCM optimal iv len
          iv(0) = (nonce >> 24).toByte
          iv(1) = (nonce >> 16).toByte
          iv(2) = (nonce >> 8).toByte
          iv(3) = nonce.toByte
          System.arraycopy(fixedCounter, 0, iv, 4, 8)
          Iv[A, CTR](iv)
        }
    }

  def ciphertextFromArray(array: Array[Byte]): Either[CipherTextError, CipherText[A, GCM, NoPadding]] =
    CipherText.fromArray[A, GCM, NoPadding, SecretKey](array)
}

object AES128GCM extends AESGCMConstruction[AES128]

object AES192GCM extends AESGCMConstruction[AES192]

object AES256GCM extends AESGCMConstruction[AES256]
