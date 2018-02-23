package tsec.signature

package object core {

  type CryptoSignature[A] = CryptoSignature.Sig[A]

  object CryptoSignature {
    type Sig[A] <: Array[Byte]

    def apply[A](value: Array[Byte]) = value.asInstanceOf[CryptoSignature[A]]

    def subst[A]: PartiallyApplied[A] = new PartiallyApplied[A]

    private[core] final class PartiallyApplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[Array[Byte]]): F[CryptoSignature[A]] = value.asInstanceOf[F[CryptoSignature[A]]]
    }
  }

}
