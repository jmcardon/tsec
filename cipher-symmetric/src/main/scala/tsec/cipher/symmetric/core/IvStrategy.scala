package tsec.cipher.symmetric.core

import cats.effect.Sync
import tsec.cipher.symmetric.imports.{Cipher, CipherMode}
import tsec.common.ManagedRandom

trait IvStrategy[A, M] {

  def genIv[F[_]](implicit F: Sync[F]): F[Iv[A, M]] = F.delay(genIvUnsafe)

  def genIvUnsafe: Iv[A, M]

}

object IvStrategy {
  private[tsec] def defaultStrategy[A, M: CipherMode](implicit C: Cipher[A]) =
    new IvStrategy[A, M] with ManagedRandom {
      def genIvUnsafe: Iv[A, M] = {
        val nonce = new Array[Byte](C.blockSizeBytes)
        nextBytes(nonce)
        Iv[A, M](nonce)
      }
    }

  private[tsec] def emptyIv[A, M: CipherMode] =
    new IvStrategy[A, M] {
      protected val cachedEmpty = Array.empty[Byte]
      def genIvUnsafe: Iv[A, M] = Iv[A, M](cachedEmpty)
    }
}
