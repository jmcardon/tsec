package tsec.signature

import java.security.cert.Certificate
import java.security.PrivateKey
import java.security.PublicKey

import cats.Monad
import cats.effect.Sync
import cats.instances.either._
import cats.syntax.all._
import tsec.signature.core._

package object imports {
  type SigErrorM[A] = Either[Throwable, A]

  type SigCertificate[A] = SigCertificate.Repr[A]

  object SigCertificate {
    type Repr[A]

    @inline def apply[A: SigAlgoTag](cert: Certificate): SigCertificate[A] = cert.asInstanceOf[SigCertificate[A]]
    @inline def toJavaCertificate[A](cert: SigCertificate[A]): Certificate = cert.asInstanceOf[Certificate]
  }

  type SigPublicKey[A] = SigPublicKey.Repr[A]

  object SigPublicKey {
    type Repr[A]

    @inline def apply[A: SigAlgoTag](key: PublicKey): SigPublicKey[A] = key.asInstanceOf[SigPublicKey[A]]
    @inline def toJavaPublicKey[A](key: SigPublicKey[A]): PublicKey   = key.asInstanceOf[PublicKey]
  }

  type SigPrivateKey[A] = SigPrivateKey.Repr[A]

  object SigPrivateKey {
    type Repr[A]

    @inline def apply[A: SigAlgoTag](key: PrivateKey): SigPrivateKey[A] = key.asInstanceOf[SigPrivateKey[A]]
    @inline def toJavaPrivateKey[A](key: SigPrivateKey[A]): PrivateKey  = key.asInstanceOf[PrivateKey]
  }

  import tsec.signature.core.{CertificateSigner, CryptoSignature, JCASigAlgebra, SigAlgoTag}

  class JCASigner[F[_]: Monad, A: SigAlgoTag](
      algebra: JCASigAlgebra[F, A, SigPublicKey, SigPrivateKey, SigCertificate]
  ) extends CertificateSigner[F, A, SigPublicKey, SigPrivateKey, SigCertificate] {

    def sign(content: Array[Byte], p: SigPrivateKey[A]): F[CryptoSignature[A]] =
      for {
        instance <- algebra.genSignatureInstance
        _        <- algebra.initSign(instance, p)
        _        <- algebra.loadBytes(content, instance)
        signed   <- algebra.sign(instance)
      } yield CryptoSignature[A](signed)

    def verify(toSign: Array[Byte], signed: CryptoSignature[A], k: SigPublicKey[A]): F[Boolean] =
      for {
        instance <- algebra.genSignatureInstance
        _        <- algebra.initVerifyK(instance, k)
        _        <- algebra.loadBytes(toSign, instance)
        verified <- algebra.verify(signed, instance)
      } yield verified

    def verifyCert(toSign: Array[Byte], signed: CryptoSignature[A], c: SigCertificate[A]): F[Boolean] =
      for {
        instance <- algebra.genSignatureInstance
        _        <- algebra.initVerifyC(instance, c)
        _        <- algebra.loadBytes(toSign, instance)
        verified <- algebra.verify(signed, instance)
      } yield verified

  }

  implicit def signer[F[_]: Sync, A: SigAlgoTag](
      implicit C: JCASigInterpreter[F, A]
  ): JCASigner[F, A] = new JCASigner[F, A](C)

  implicit def impureSigner[A: SigAlgoTag](implicit jCASigner: JCASigInterpreterImpure[A]): JCASigner[SigErrorM, A] =
    new JCASigner(jCASigner)

}
