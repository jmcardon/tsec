package tsec.mac

package object core {

  type MAC[A] = MAC.Type[A]

  object MAC {
    type Type[A] <: Array[Byte]

    def apply[A](value: Array[Byte]): MAC[A] = value.asInstanceOf[MAC[A]]
    def subst[A]: PartiallyApplied[A] = new PartiallyApplied[A]

    private[core] final class PartiallyApplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[Array[Byte]]): F[MAC[A]] = value.asInstanceOf[F[MAC[A]]]
    }

    def unsubst[A]: PartiallyUnapplied[A] = new PartiallyUnapplied[A]

    private[tsec] final class PartiallyUnapplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[MAC[A]]): F[Array[Byte]] = value.asInstanceOf[F[Array[Byte]]]
    }
  }

}
