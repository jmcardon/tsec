package tsec.signature

package object libsodium {

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

  type PrivateKey[A] = PrivateKey.Type[A]

  //Todo: Check keyLen for building.
  object PrivateKey {
    type Type[A] <: Array[Byte]

    def apply[A](value: Array[Byte]): PrivateKey[A] = value.asInstanceOf[PrivateKey[A]]
    def subst[A]: PartiallyApplied[A]               = new PartiallyApplied[A]

    private[tsec] final class PartiallyApplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[Array[Byte]]): F[PrivateKey[A]] = value.asInstanceOf[F[PrivateKey[A]]]
    }

    def unsubst[A]: PartiallyUnapplied[A] = new PartiallyUnapplied[A]

    private[tsec] final class PartiallyUnapplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[PrivateKey[A]]): F[Array[Byte]] = value.asInstanceOf[F[Array[Byte]]]
    }
  }

  type PublicKey[A] = PublicKey.Type[A]

  object PublicKey {
    type Type[A] <: Array[Byte]

    def apply[A](value: Array[Byte]): PublicKey[A] = value.asInstanceOf[PublicKey[A]]
    def subst[A]: PartiallyApplied[A]               = new PartiallyApplied[A]

    private[tsec] final class PartiallyApplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[Array[Byte]]): F[PublicKey[A]] = value.asInstanceOf[F[PublicKey[A]]]
    }

    def unsubst[A]: PartiallyUnapplied[A] = new PartiallyUnapplied[A]

    private[tsec] final class PartiallyUnapplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[PublicKey[A]]): F[Array[Byte]] = value.asInstanceOf[F[Array[Byte]]]
    }
  }

  final case class SodiumKeyPair[A](pubKey: PublicKey[A], privKey: PrivateKey[A])

}
