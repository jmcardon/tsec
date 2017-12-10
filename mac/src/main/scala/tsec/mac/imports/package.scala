package tsec.mac

import cats.evidence.Is
import tsec.common._
import javax.crypto.{SecretKey => JSecretKey}

import tsec.mac.core.MacTag

package object imports {

  type MacErrorM[A] = Either[Throwable, A]

  trait MacKeyGenerator[A] extends JKeyGenerator[A, MacSigningKey, MacKeyBuildError]

  sealed trait TaggedMacKey {
    type Repr[A]
    def is[A]: Is[Repr[A], JSecretKey]
  }

  protected val MacSigningKey$$ : TaggedMacKey = new TaggedMacKey {
    type Repr[A] = JSecretKey
    @inline def is[A]: Is[Repr[A], JSecretKey] = Is.refl[JSecretKey]
  }

  type MacSigningKey[A] = MacSigningKey$$.Repr[A]

  object MacSigningKey {
    def is[A]: Is[MacSigningKey[A], JSecretKey]                           = MacSigningKey$$.is[A]
    @inline def fromJavaKey[A: MacTag](key: JSecretKey): MacSigningKey[A] = MacSigningKey$$.is[A].flip.coerce(key)
    @inline def toJavaKey[A: MacTag](key: MacSigningKey[A]): JSecretKey   = MacSigningKey$$.is[A].coerce(key)
  }

  final class SigningKeyOps[A](val key: MacSigningKey[A]) extends AnyVal {
    def toJavaKey: JSecretKey = MacSigningKey$$.is.coerce(key)
  }

  implicit final def _macSigningOps[A](key: MacSigningKey[A]) = new SigningKeyOps[A](key)
}
