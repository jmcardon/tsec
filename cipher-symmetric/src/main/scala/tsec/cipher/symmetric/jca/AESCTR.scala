package tsec.cipher.symmetric.jca

import java.util.concurrent.atomic.AtomicLong

import cats.effect.Sync
import tsec.cipher.common.padding.NoPadding
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.jca.primitive.JCAPrimitiveCipher

sealed abstract class AESCTR[A] extends JCACipherAPI[A, CTR, NoPadding] with AES[A] with JCAKeyGen[A] {
  implicit val ae: AESCTR[A] = this

  def genEncryptor[F[_]: Sync](implicit c: BlockCipher[A]): F[Encryptor[F, A, SecretKey]] =
    JCAPrimitiveCipher.sync[F, A, CTR, NoPadding]()

  /** Our default Iv strategy for CTR mode
    * produces randomized IVs
    *
    *
    * @return
    */
  def defaultIvStrategy[F[_]: Sync](implicit c: BlockCipher[A]): IvGen[F, A] = JCAIvGen.random[F, A]

  /** An incremental iv generator, intended for use
    * with a single key.
    *
    * See: https://crypto.stanford.edu/~dabo/cs255/lectures/PRP-PRF.pdf,
    * courtesy of dan boneh
    *
    * For a 128 bit iv, we use a 64 bit leftmost bits as a nonce,
    * and the rightmost 64 bits (zeroed out) as the counter.
    *
    * This means, using the `incremental` strategy, you can safely generate
    * generate 2^64 - 10^6 different nonces maximum, each of which can safely increment
    * a maximum of 2^64 blocks.
    *
    * 2^64 - 10^6 is a safe limit to possibly avoid overflowing the safe number of nonces you can
    * generate with one key.
    *
    * @return
    */
  def incrementalIvStrategy[F[_]](implicit F: Sync[F]): CounterIvGen[F, A] =
    new CounterIvGen[F, A] {
      private val delta                     = 1000000L
      private val maxVal: Long              = Long.MaxValue - delta
      private val fixedCounter: Array[Byte] = Array.fill[Byte](8)(0.toByte)
      private val atomicNonce: AtomicLong   = new AtomicLong(Long.MinValue)

      def refresh: F[Unit] = F.delay(atomicNonce.set(Long.MinValue))

      def counterState: F[Long] = F.delay(unsafeCounterState)

      def unsafeCounterState: Long = atomicNonce.get()

      def genIv: F[Iv[A]] =
        F.delay(genIvUnsafe)

      def genIvUnsafe: Iv[A] =
        if (atomicNonce.get() >= maxVal) {
          throw IvError("Maximum safe nonce number reached")
        } else {
          val nonce = atomicNonce.incrementAndGet()
          val iv    = new Array[Byte](16) //AES block size
          iv(0) = (nonce >> 56).toByte
          iv(1) = (nonce >> 48).toByte
          iv(2) = (nonce >> 40).toByte
          iv(3) = (nonce >> 32).toByte
          iv(4) = (nonce >> 24).toByte
          iv(5) = (nonce >> 16).toByte
          iv(6) = (nonce >> 8).toByte
          iv(7) = nonce.toByte
          System.arraycopy(fixedCounter, 0, iv, 8, 8)
          Iv[A](iv)
        }
    }

  @deprecated("use ciphertextFromConcat", "0.0.1-M10")
  def ciphertextFromArray(array: Array[Byte]): Either[CipherTextError, CipherText[A]] =
    ciphertextFromConcat(array)

  def ciphertextFromConcat(rawCT: Array[Byte]): Either[CipherTextError, CipherText[A]] =
    CTOPS.ciphertextFromArray[A, CTR, NoPadding](rawCT)
}

sealed trait AES128CTR

object AES128CTR extends AESCTR[AES128CTR] with AES128[AES128CTR]

sealed trait AES192CTR

object AES192CTR extends AESCTR[AES192CTR] with AES192[AES192CTR]

sealed trait AES256CTR

object AES256CTR extends AESCTR[AES256CTR] with AES256[AES256CTR]
