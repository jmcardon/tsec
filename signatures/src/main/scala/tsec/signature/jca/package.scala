package tsec.signature

import java.security.{PrivateKey, PublicKey}
import java.security.cert.Certificate

package object jca {
  type SigErrorM[A] = Either[Throwable, A]

  type SigCertificate[A] = SigCertificate.Repr[A]

  object SigCertificate {
    type Repr[A]

    @inline def apply[A](cert: Certificate): SigCertificate[A]             = cert.asInstanceOf[SigCertificate[A]]
    @inline def toJavaCertificate[A](cert: SigCertificate[A]): Certificate = cert.asInstanceOf[Certificate]
  }

  type SigPublicKey[A] = SigPublicKey.Repr[A]

  object SigPublicKey {
    type Repr[A]

    @inline def apply[A](key: PublicKey): SigPublicKey[A]           = key.asInstanceOf[SigPublicKey[A]]
    @inline def toJavaPublicKey[A](key: SigPublicKey[A]): PublicKey = key.asInstanceOf[PublicKey]
  }

  type SigPrivateKey[A] = SigPrivateKey.Repr[A]

  object SigPrivateKey {
    type Repr[A]

    @inline def apply[A](key: PrivateKey): SigPrivateKey[A]            = key.asInstanceOf[SigPrivateKey[A]]
    @inline def toJavaPrivateKey[A](key: SigPrivateKey[A]): PrivateKey = key.asInstanceOf[PrivateKey]
  }
//  implicit def signer[F[_]: Sync, A](
//      implicit C: JCASigInterpreter[F, A]
//  ): JCASigner[F, A] = new JCASigner[F, A](C)
//
//  implicit def impureSigner[A](implicit jCASigner: JCASigInterpreterImpure[A]): JCASigner[SigErrorM, A] =
//    new JCASigner(jCASigner)

}
