package tsec.signature

import tsec.signature.core.SigAlgoTag

package object imports {
  type SigErrorM[A] = Either[Throwable, A]


  import java.security.cert.Certificate

  import cats.evidence.Is
  import java.security.PrivateKey
  import java.security.PublicKey

  sealed trait TaggedCertificate {
    type Repr[A]
    def is[A]: Is[Repr[A], Certificate]
  }

  protected val SigCertificate$$ : TaggedCertificate = new TaggedCertificate {
    type Repr[A] = Certificate
    @inline def is[A]: Is[Repr[A], Certificate] = Is.refl[Certificate]
  }

  type SigCertificate[A] = SigCertificate$$.Repr[A]

  object SigCertificate {
    @inline def apply[A: SigAlgoTag](cert: Certificate): SigCertificate[A] = SigCertificate$$.is[A].flip.coerce(cert)
    @inline def toJavaCertificate[A](cert: SigCertificate[A]): Certificate = SigCertificate$$.is[A].coerce(cert)
  }

  sealed trait TaggedSigPubKey {
    type Repr[A]
    def is[A]: Is[Repr[A], PublicKey]
  }

  protected val SigPubKey$$ : TaggedSigPubKey = new TaggedSigPubKey {
    type Repr[A] = PublicKey
    def is[A]: Is[Repr[A], PublicKey] = Is.refl[PublicKey]
  }

  type SigPublicKey[A] = SigPubKey$$.Repr[A]

  object SigPublicKey {
    @inline def apply[A: SigAlgoTag](key: PublicKey): SigPublicKey[A] = SigPubKey$$.is[A].flip.coerce(key)
    @inline def toJavaPublicKey[A](key: SigPublicKey[A]): PublicKey   = SigPubKey$$.is[A].coerce(key)
  }

  sealed trait TaggedSigPrivateKey {
    type Repr[A]
    def is[A]: Is[Repr[A], PrivateKey]
  }

  protected val SigPrivateKey$$ : TaggedSigPrivateKey = new TaggedSigPrivateKey {
    type Repr[A] = PrivateKey
    @inline def is[A]: Is[Repr[A], PrivateKey] = Is.refl[PrivateKey]
  }

  type SigPrivateKey[A] = SigPrivateKey$$.Repr[A]

  object SigPrivateKey {
    @inline def apply[A: SigAlgoTag](key: PrivateKey): SigPrivateKey[A] = SigPrivateKey$$.is[A].flip.coerce(key)
    @inline def toJavaPrivateKey[A](key: SigPrivateKey[A]): PrivateKey  = SigPrivateKey$$.is[A].coerce(key)
  }

}
