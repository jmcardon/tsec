package tsec.libsodium.pk

package object encryption {

  type PKAuthTag[A] = PKAuthTag.Type[A]

  object PKAuthTag {
    type Type[A] <: Array[Byte]

    def apply[A](bytes: Array[Byte]): PKAuthTag[A] = bytes.asInstanceOf[PKAuthTag[A]]

    def subst[A]: PKAuthPartiallyApplied[A] = new PKAuthPartiallyApplied[A]

    private[tsec] final class PKAuthPartiallyApplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[Array[Byte]]): F[PKAuthTag[A]] = value.asInstanceOf[F[PKAuthTag[A]]]
    }

    def unsubst[A]: PartiallyUnapplied[A] = new PartiallyUnapplied[A]

    private[tsec] final class PartiallyUnapplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[PKAuthTag[A]]): F[Array[Byte]] = value.asInstanceOf[F[Array[Byte]]]
    }
  }

  type SharedKey[A] = SharedKey.Type[A]

  object SharedKey {
    type Type[A] <: Array[Byte]

    def apply[A](bytes: Array[Byte]): SharedKey[A] = bytes.asInstanceOf[SharedKey[A]]

    def subst[A]: PartiallyApplied[A] = new PartiallyApplied[A]

    private[tsec] final class PartiallyApplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[Array[Byte]]): F[SharedKey[A]] = value.asInstanceOf[F[SharedKey[A]]]
    }

    def unsubst[A]: PartiallyUnapplied[A] = new PartiallyUnapplied[A]

    private[tsec] final class PartiallyUnapplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[SharedKey[A]]): F[Array[Byte]] = value.asInstanceOf[F[Array[Byte]]]
    }
  }
}
