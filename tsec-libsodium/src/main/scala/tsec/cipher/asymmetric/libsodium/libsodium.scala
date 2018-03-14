package tsec.cipher.asymmetric

package object libsodium {

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
