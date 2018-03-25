package tsec.cipher.symmetric

package object bouncy {


  type BouncySecretKey[A] = BouncySecretKey.Type[A]

  object BouncySecretKey {

    type Type[A] <: Array[Byte]

    def apply[A](key: Array[Byte]): BouncySecretKey[A]     = key.asInstanceOf[BouncySecretKey[A]]
    def toJavaKey[A](key: BouncySecretKey[A]): Array[Byte] = key.asInstanceOf[Array[Byte]]
    def subst[A]: SecretKPartiallyApplied[A]        = new SecretKPartiallyApplied[A]

    private[tsec] class SecretKPartiallyApplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[Array[Byte]]): F[BouncySecretKey[A]] = value.asInstanceOf[F[BouncySecretKey[A]]]
    }

    def unsubst[A]: SecretKUnwrap[A] = new SecretKUnwrap[A]

    private[tsec] class SecretKUnwrap[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[BouncySecretKey[A]]): F[Array[Byte]] = value.asInstanceOf[F[Array[Byte]]]
    }
  }

}
