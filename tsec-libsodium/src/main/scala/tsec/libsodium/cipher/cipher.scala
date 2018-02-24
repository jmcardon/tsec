package tsec.libsodium

package object cipher {

  /** Our newtype over private keys **/
  type SodiumKey[A] = SodiumKey.Type[A]

  object SodiumKey {
    type Type[A] <: Array[Byte]

    def apply[A](bytes: Array[Byte]): SodiumKey[A] = bytes.asInstanceOf[SodiumKey[A]]

    def subst[A]: PartiallyApplied[A] = new PartiallyApplied[A]

    private[tsec] final class PartiallyApplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[Array[Byte]]): F[SodiumKey[A]] = value.asInstanceOf[F[SodiumKey[A]]]
    }
  }

  type CryptoStreamHeader = CryptoStreamHeader.Type

  object CryptoStreamHeader {
    type Type <: Array[Byte]

    def apply[A](bytes: Array[Byte]): CryptoStreamHeader          = bytes.asInstanceOf[CryptoStreamHeader]
    def subst[F[_]](value: F[Array[Byte]]): F[CryptoStreamHeader] = value.asInstanceOf[F[CryptoStreamHeader]]
  }

  private[tsec] type CryptoStreamState = CryptoStreamState.Type

  object CryptoStreamState {
    type Type <: Array[Byte]

    def apply[A](bytes: Array[Byte]): CryptoStreamState          = bytes.asInstanceOf[CryptoStreamState]
    def subst[F[_]](value: F[Array[Byte]]): F[CryptoStreamState] = value.asInstanceOf[F[CryptoStreamState]]
  }
}
