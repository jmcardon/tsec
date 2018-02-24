package tsec.libsodium

import tsec.libsodium.hashing.internal.SodiumHash

package object hashing {
  type HashState[A] = HashState.Type[A]

  object HashState {
    type Type[A] <: Array[Byte]

    def apply[A: SodiumHash](bytes: Array[Byte]): HashState[A] = bytes.asInstanceOf[HashState[A]]

    def subst[A]: PartiallyApplied[A] = new PartiallyApplied[A]

    private[tsec] final class PartiallyApplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[Array[Byte]]): F[HashState[A]] = value.asInstanceOf[F[HashState[A]]]
    }

    def unsubst[A]: PartiallyUnapplied[A] = new PartiallyUnapplied[A]

    private[tsec] final class PartiallyUnapplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[HashState[A]]): F[Array[Byte]] = value.asInstanceOf[F[Array[Byte]]]
    }
  }

  type BlakeKey = BlakeKey.Type

  object BlakeKey {
    type Type <: Array[Byte]

    def apply(bytes: Array[Byte]): BlakeKey               = bytes.asInstanceOf[BlakeKey]
    def subst[F[_]](value: F[Array[Byte]]): F[BlakeKey]   = value.asInstanceOf[F[BlakeKey]]
    def unsubst[F[_]](value: F[BlakeKey]): F[Array[Byte]] = value.asInstanceOf[F[Array[Byte]]]
  }
}
