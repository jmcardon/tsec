package tsec.libsodium.pk

package object signatures {

  type RawMessage[A] = RawMessage.Type[A]

  object RawMessage {
    type Type[A] <: Array[Byte]

    def apply[A](value: Array[Byte]): RawMessage[A] = value.asInstanceOf[RawMessage[A]]
    def subst[A]: PartiallyApplied[A]               = new PartiallyApplied[A]

    private[tsec] final class PartiallyApplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[Array[Byte]]): F[RawMessage[A]] = value.asInstanceOf[F[RawMessage[A]]]
    }

    def unsubst[A]: PartiallyUnapplied[A] = new PartiallyUnapplied[A]

    private[tsec] final class PartiallyUnapplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[RawMessage[A]]): F[Array[Byte]] = value.asInstanceOf[F[Array[Byte]]]
    }
  }

  type SignedMessage[A] = SignedMessage.Type[A]

  object SignedMessage {
    type Type[A] <: Array[Byte]

    def apply[A](value: Array[Byte]): SignedMessage[A] = value.asInstanceOf[SignedMessage[A]]
    def subst[A]: PartiallyApplied[A]                  = new PartiallyApplied[A]

    private[tsec] final class PartiallyApplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[Array[Byte]]): F[SignedMessage[A]] = value.asInstanceOf[F[SignedMessage[A]]]
    }

    def unsubst[A]: PartiallyUnapplied[A] = new PartiallyUnapplied[A]

    private[tsec] final class PartiallyUnapplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[SignedMessage[A]]): F[Array[Byte]] = value.asInstanceOf[F[Array[Byte]]]
    }
  }

}
