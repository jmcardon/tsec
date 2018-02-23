package tsec.hashing

package object core {

  type CryptoHash[A] = CryptoHash.Type[A]

  object CryptoHash {
    type Type[A] <: Array[Byte]

    def apply[A](value: Array[Byte]): CryptoHash[A] = value.asInstanceOf[CryptoHash[A]]
    def subst[A]: PartiallyApplied[A]         = new PartiallyApplied[A]

    private[core] final class PartiallyApplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[Array[Byte]]): F[CryptoHash[A]] = value.asInstanceOf[F[CryptoHash[A]]]
    }
  }

}
