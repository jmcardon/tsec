package tsec.cipher.symmetric.imports

import java.util.concurrent.atomic.AtomicLong

import cats.effect.Sync
import tsec.cipher.common.padding.NoPadding
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.core.{CounterIvStrategy, Iv, IvStrategy}
import tsec.cipher.symmetric.imports.primitive.JCAPrimitiveCipher

sealed abstract class AESCTRConstruction[A: AES] extends JCACipher[A, CTR, NoPadding, CTRCipherText[A]] {

  def genEncryptor[F[_]: Sync]: F[CTREncryptor[F, A]] = JCAPrimitiveCipher[F, A, CTR, NoPadding]()

  /** Our default Iv strategy for CTR mode
    * produces randomized IVs
    *
    *
    * @return
    */
  def defaultIvStrategy: IvStrategy[A, CTR] = IvStrategy.defaultStrategy[A, CTR]

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
  def incrementalIvStrategy: CounterIvStrategy[A, CTR] =
    new CounterIvStrategy[A, CTR] {
      private val delta                     = 1000000L
      private val maxVal: Long              = Long.MaxValue - delta
      private val numGen: AtomicLong        = new AtomicLong(Long.MinValue)
      private val fixedCounter: Array[Byte] = Array.fill[Byte](8)(0.toByte)
      private val atomicNonce: AtomicLong   = new AtomicLong(Long.MinValue)

      def numGenerated[F[_]](implicit F: Sync[F]): F[Long] = F.delay(unsafeNumGenerated)

      def unsafeNumGenerated: Long = numGen.get()

      def genIv[F[_]](implicit F: Sync[F]): F[Iv[A, CTR]] =
        F.delay(genIvUnsafe)

      def genIvUnsafe: Iv[A, CTR] =
        if (numGen.get() >= maxVal)
          throw IvError("Maximum safe nonce number reached")
        else {
          numGen.incrementAndGet()
          val nonce  = atomicNonce.incrementAndGet()
          val iv = new Array[Byte](16) //AES block size
          iv(0) = (nonce >> 56).toByte
          iv(1) = (nonce >> 48).toByte
          iv(2) = (nonce >> 40).toByte
          iv(3) = (nonce >> 32).toByte
          iv(4) = (nonce >> 24).toByte
          iv(5) = (nonce >> 16).toByte
          iv(6) = (nonce >> 8).toByte
          iv(7) = nonce.toByte
          System.arraycopy(fixedCounter, 0, iv, 8, 8)
          Iv[A, CTR](iv)
        }
    }

  def ciphertextFromArray(array: Array[Byte]): Either[CipherTextError, CipherText[A, CTR, NoPadding]] =
    CipherText.fromArray[A, CTR, NoPadding, SecretKey](array)

}

object AES128CTR extends AESCTRConstruction[AES128]

object AES192CTR extends AESCTRConstruction[AES192]

object AES256CTR extends AESCTRConstruction[AES256]
