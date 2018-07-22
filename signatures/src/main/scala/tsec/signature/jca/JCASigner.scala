package tsec.signature.jca

import cats.Monad
import tsec.signature.{CertificateSigner, CryptoSignature}
import cats.syntax.functor._
import cats.syntax.flatMap._

abstract class JCASigner[F[_]: Monad, A](
    algebra: JCASigAlgebra[F, A, SigPublicKey, SigPrivateKey, SigCertificate]
) extends CertificateSigner[F, A, SigPublicKey, SigPrivateKey, SigCertificate] {

  def sign(content: Array[Byte], p: SigPrivateKey[A]): F[CryptoSignature[A]] =
    for {
      instance <- algebra.genSignatureInstance
      _        <- algebra.initSign(instance, p)
      _        <- algebra.loadBytes(content, instance)
      signed   <- algebra.sign(instance)
    } yield CryptoSignature[A](signed)

  def verifyBool(toSign: Array[Byte], signed: CryptoSignature[A], k: SigPublicKey[A]): F[Boolean] =
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
