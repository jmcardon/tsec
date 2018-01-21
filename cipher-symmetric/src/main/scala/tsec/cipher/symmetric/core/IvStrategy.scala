package tsec.cipher.symmetric.core

import java.util.concurrent.atomic.AtomicLong

import cats.effect.Sync
import tsec.cipher.symmetric.imports.{BlockCipher, CipherMode}
import tsec.common.ManagedRandom

trait IvStrategy[A, M] {

  def genIv[F[_]](implicit F: Sync[F]): F[Iv[A, M]]

  def genIvUnsafe: Iv[A, M]

}

object IvStrategy {
  def defaultStrategy[A, M: CipherMode](implicit C: BlockCipher[A]): IvStrategy[A, M] =
    new IvStrategy[A, M] with ManagedRandom {

      def genIv[F[_]](implicit F: Sync[F]): F[Iv[A, M]] =
        F.delay(genIvUnsafe)

      def genIvUnsafe: Iv[A, M] = {
        val nonce = new Array[Byte](C.blockSizeBytes)
        nextBytes(nonce)
        Iv[A, M](nonce)
      }
    }

  def emptyIv[A, M: CipherMode]: IvStrategy[A, M] =
    new IvStrategy[A, M] {

      def genIv[F[_]](implicit F: Sync[F]): F[Iv[A, M]] =
        F.pure(Iv[A, M](cachedEmpty))

      protected val cachedEmpty                   = Array.empty[Byte]
      def genIvUnsafe: Iv[A, M] = Iv[A, M](cachedEmpty)
    }
}

trait CounterIvStrategy[A, M] extends IvStrategy[A, M] {
  def numGenerated[F[_]](implicit F: Sync[F]): F[Long]

  def unsafeNumGenerated: Long
}

private[tsec] class FailedAtomicLong extends AtomicLong {

}