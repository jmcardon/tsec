package tsec.cipher.symmetric.core

import cats.effect.Sync
import tsec.cipher.symmetric.imports.{BlockCipher, CipherMode}
import tsec.common.ManagedRandom

trait IvStrategy[A, M] {

  def genIv[F[_]](ptSizeBytes: Int)(implicit F: Sync[F]): F[Iv[A, M]] =
    F.delay(genIvUnsafe(ptSizeBytes))

  def genIvUnsafe(ptSizeBytes: Int): Iv[A, M]

}

object IvStrategy {
  private[tsec] def defaultStrategy[A, M: CipherMode](implicit C: BlockCipher[A]): IvStrategy[A, M] =
    new IvStrategy[A, M] with ManagedRandom {
      def genIvUnsafe(ptSizeBytes: Int): Iv[A, M] = {
        val nonce = new Array[Byte](C.blockSizeBytes)
        nextBytes(nonce)
        Iv[A, M](nonce)
      }
    }

  private[tsec] def emptyIv[A, M: CipherMode]: IvStrategy[A, M] =
    new IvStrategy[A, M] {
      protected val cachedEmpty                   = Array.empty[Byte]
      def genIvUnsafe(ptSizeBytes: Int): Iv[A, M] = Iv[A, M](cachedEmpty)
    }
}
