package tsec.cipher.symmetric

package object core {
  type Iv[A] = Iv.Type[A]

  object Iv {
    type Type[A] <: Array[Byte]

    def apply[A](value: Array[Byte]): Iv[A] = value.asInstanceOf[Iv[A]]
    def subst[A]: PartiallyApplied[A]       = new PartiallyApplied[A]

    private[core] final class PartiallyApplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[Array[Byte]]): F[Iv[A]] =
        value.asInstanceOf[F[Iv[A]]]
    }
  }

  type RawCipherText[A] = RawCipherText.Type[A]

  object RawCipherText {
    type Type[A] <: Array[Byte]

    def apply[A](value: Array[Byte]): RawCipherText[A] = value.asInstanceOf[RawCipherText[A]]
    def subst[A]: PartiallyApplied[A]                  = new PartiallyApplied[A]

    private[core] final class PartiallyApplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[Array[Byte]]): F[RawCipherText[A]] =
        value.asInstanceOf[F[RawCipherText[A]]]
    }
  }

  type Nonce[A] = Nonce.Type[A]

  object Nonce {
    type Type[A] <: Array[Byte]
    def apply[A](value: Array[Byte]): Nonce[A] = value.asInstanceOf[Nonce[A]]

    def subst[A]: NoncePartiallyApplied[A] = new NoncePartiallyApplied[A]

    private[core] final class NoncePartiallyApplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[Array[Byte]]): F[Nonce[A]] =
        value.asInstanceOf[F[Nonce[A]]]
    }
  }

  type PlainText = PlainText.Type

  object PlainText {
    type Type <: Array[Byte]

    def apply(value: Array[Byte]): PlainText             = value.asInstanceOf[PlainText]
    def subst[F[_]](value: F[Array[Byte]]): F[PlainText] = value.asInstanceOf[F[PlainText]]
  }

  type AAD = AAD.Type

  object AAD {
    type Type <: Array[Byte]

    def apply(value: Array[Byte]): AAD             = value.asInstanceOf[AAD]
    def subst[F[_]](value: F[Array[Byte]]): F[AAD] = value.asInstanceOf[F[AAD]]
  }

  type AuthTag[A]

  object AuthTag {
    type Type[A] <: Array[Byte]

    def apply[A](value: Array[Byte]): AuthTag[A] = value.asInstanceOf[AuthTag[A]]

    def subst[A]: AuthTagPartiallyApplied[A] = new AuthTagPartiallyApplied[A]

    private[core] final class AuthTagPartiallyApplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[Array[Byte]]): F[AuthTag[A]] =
        value.asInstanceOf[F[AuthTag[A]]]
    }
  }

  case class CipherText[A](cipherText: RawCipherText[A], nonce: Nonce[A])

}
