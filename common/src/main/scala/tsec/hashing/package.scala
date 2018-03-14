package tsec

package object hashing {

  type CryptoHash[A] = CryptoHash.Type[A]

  object CryptoHash {
    type Type[A] <: Array[Byte]

    def apply[A](value: Array[Byte]): CryptoHash[A] = value.asInstanceOf[CryptoHash[A]]
    def subst[A]: PartiallyApplied[A]               = new PartiallyApplied[A]

    private[tsec] final class PartiallyApplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[Array[Byte]]): F[CryptoHash[A]] = value.asInstanceOf[F[CryptoHash[A]]]
    }

    def unsubst[A]: PartiallyUnapplied[A] = new PartiallyUnapplied[A]

    private[tsec] final class PartiallyUnapplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[CryptoHash[A]]): F[Array[Byte]] = value.asInstanceOf[F[Array[Byte]]]
    }
  }

}
