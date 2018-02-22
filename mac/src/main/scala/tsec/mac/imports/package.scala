package tsec.mac

import tsec.common._
import javax.crypto.{SecretKey => JSecretKey}

import tsec.mac.core.JCAMacTag

package object imports {

  type MacErrorM[A] = Either[Throwable, A]

  trait MacKeyGenerator[A] extends JKeyGenerator[A, MacSigningKey, MacKeyBuildError]

  type MacSigningKey[A] = MacSigningKey.Type[A]

  object MacSigningKey {
    type Base$$1
    trait Tag$$1 extends Any
    type Type[A] <: Base$$1 with Tag$$1

    @inline def fromJavaKey[A: JCAMacTag](key: JSecretKey): MacSigningKey[A] = key.asInstanceOf[MacSigningKey[A]]
    @inline def toJavaKey[A: JCAMacTag](key: MacSigningKey[A]): JSecretKey   = key.asInstanceOf[JSecretKey]
    def subst[A]: SKPartiallyApplied[A]                                   = new SKPartiallyApplied[A]()

    private[tsec] class SKPartiallyApplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[JSecretKey]): F[MacSigningKey[A]] = value.asInstanceOf[F[MacSigningKey[A]]]
    }
  }

  final class SigningKeyOps[A](val key: MacSigningKey[A]) extends AnyVal {
    def toJavaKey(implicit m: JCAMacTag[A]): JSecretKey = MacSigningKey.toJavaKey[A](key)
  }

  implicit final def _macSigningOps[A](key: MacSigningKey[A]): SigningKeyOps[A] = new SigningKeyOps[A](key)
}
