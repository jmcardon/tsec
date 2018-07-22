package tsec.mac

import javax.crypto.{SecretKey => JSecretKey}
import tsec.keygen.symmetric.{SymmetricKeyGen, SymmetricKeyGenAPI}

package object jca {

  type MacErrorM[A] = Either[Throwable, A]

  trait MacKeyGenerator[A] extends SymmetricKeyGenAPI[A, MacSigningKey]

  type MacSigningKey[A] = MacSigningKey.Type[A]

  type MacKeyGen[F[_], A] = SymmetricKeyGen[F, A, MacSigningKey]

  object MacSigningKey {
    type Base1
    trait Tag1 extends Any
    type Type[A] <: Base1 with Tag1
    @inline def apply[A](key: JSecretKey): MacSigningKey[A]       = key.asInstanceOf[MacSigningKey[A]]
    @inline def fromJavaKey[A](key: JSecretKey): MacSigningKey[A] = key.asInstanceOf[MacSigningKey[A]]
    @inline def toJavaKey[A](key: MacSigningKey[A]): JSecretKey   = key.asInstanceOf[JSecretKey]
    def subst[A]: SKPartiallyApplied[A]                           = new SKPartiallyApplied[A]()

    private[tsec] class SKPartiallyApplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[JSecretKey]): F[MacSigningKey[A]] = value.asInstanceOf[F[MacSigningKey[A]]]
    }

    def unsubst[A]: PartiallyUnapplied[A] = new PartiallyUnapplied[A]

    private[tsec] final class PartiallyUnapplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[MacSigningKey[A]]): F[JSecretKey] = value.asInstanceOf[F[JSecretKey]]
    }
  }

  final class SigningKeyOps[A](val key: MacSigningKey[A]) extends AnyVal {
    def toJavaKey: JSecretKey = MacSigningKey.toJavaKey[A](key)
  }

  implicit final def _macSigningOps[A](key: MacSigningKey[A]): SigningKeyOps[A] = new SigningKeyOps[A](key)

}
