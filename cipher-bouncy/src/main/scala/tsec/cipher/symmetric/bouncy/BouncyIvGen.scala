package tsec.cipher.symmetric.bouncy

import cats.Applicative
import cats.effect.Sync
import tsec.cipher.symmetric.{BlockCipher, Iv, IvGen}
import tsec.common.ManagedRandom

object BouncyIvGen {

  def emptyIv[F[_], A](implicit F: Applicative[F]): IvGen[F, A] =
    new IvGen[F, A] {
      protected val cachedEmpty = Array.empty[Byte]

      def genIv: F[Iv[A]] =
        F.pure(Iv[A](cachedEmpty))

      def genIvUnsafe: Iv[A] = Iv[A](cachedEmpty)
    }
}
