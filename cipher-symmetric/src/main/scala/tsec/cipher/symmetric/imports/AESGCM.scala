package tsec.cipher.symmetric.imports

import java.util.concurrent.atomic.AtomicInteger

import cats.effect.Sync
import tsec.cipher.common.padding.NoPadding
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.core._
import tsec.cipher.symmetric.imports.primitive.JCAAEADPrimitive

sealed abstract class AESGCMConstruction[A] extends JCAAEAD[A, GCM, NoPadding] {

  def genEncryptor[F[_]: Sync](implicit c: AES[A]): F[AuthEncryptor[F, A, SecretKey]] =
    JCAAEADPrimitive.sync[F, A, GCM, NoPadding]()

  /** Our default Iv strategy for GCM mode
    * produces randomized IVs
    *
    *
    * @return
    */
  def defaultIvStrategy[F[_]: Sync](implicit c: AES[A]): IvGen[F, A] = GCM.randomIVStrategy[F, A]

  /** An incremental iv strategy, as referenced in the
    * nist recommendations for the GCM mode of operation
    * http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
    * where:
    *
    * The fixed field(nonce) is the leftmost 4 bytes of the IV
    * The invocation field starts as a zeroed out array as the rightmost 8 bytes
    *
    */
  def incrementalIvStrategy[F[_]](implicit F: Sync[F]): CounterIvGen[F, A] =
    new CounterIvGen[F, A] {
      private val delta                      = 1000000
      private val maxVal: Int                = Int.MaxValue - delta
      private val numGen: AtomicInteger      = new AtomicInteger(Int.MinValue)
      private val fixedCounter: Array[Byte]  = Array.fill[Byte](8)(0.toByte)
      private val atomicNonce: AtomicInteger = new AtomicInteger(Int.MinValue)

      def numGenerated: F[Long] = F.delay(unsafeNumGenerated)

      def unsafeNumGenerated: Long = numGen.get().toLong

      def genIv: F[Iv[A]] =
        F.delay(genIvUnsafe)

      def genIvUnsafe: Iv[A] =
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
          Iv[A](iv)
        }
    }

  @deprecated("use ciphertextFromConcat", "0.0.1-M10")
  def ciphertextFromArray(array: Array[Byte])(implicit a: AES[A]): Either[CipherTextError, CipherText[A]] =
    ciphertextFromConcat(array)

  def ciphertextFromConcat(rawCT: Array[Byte])(implicit a: AES[A]): Either[CipherTextError, CipherText[A]] =
    CTOPS.ciphertextFromArray[A, GCM, NoPadding](rawCT)
}

sealed trait AES128GCM

object AES128GCM extends AESGCMConstruction[AES128GCM] with AES128[AES128GCM]

sealed trait AES192GCM

object AES192GCM extends AESGCMConstruction[AES192GCM] with AES192[AES192GCM]

sealed trait AES256GCM

object AES256GCM extends AESGCMConstruction[AES256GCM] with AES256[AES256GCM]
