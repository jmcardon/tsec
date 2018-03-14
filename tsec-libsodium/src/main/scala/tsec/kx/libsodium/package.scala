package tsec.kx

import tsec.cipher.symmetric.libsodium.SodiumKey
import tsec.libsodium.ScalaSodium

package object libsodium {

  type PrivateKey[A] = PrivateKey.Type[A]

  //Todo: duplication
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

  //

  final case class SodiumSharedKeyPair[A](receive: SodiumKey[A], send: SodiumKey[A])

  case object KeySessionError extends Exception with Product with Serializable {
    def cause: String = "KeySession generation Error"
    override def fillInStackTrace(): Throwable = this
  }

  case class KeySeedingError(n: Int) extends Exception with Product with Serializable {
    def cause: String = s"Got $n seeding bytes, expected ${ScalaSodium.crypto_kx_SEEDBYTES}"
    override def fillInStackTrace(): Throwable = this
  }


}
