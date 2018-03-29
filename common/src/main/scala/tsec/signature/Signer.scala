package tsec.signature

import cats.{Functor, Id}
import tsec.common.{VerificationFailed, VerificationStatus, Verified}

trait Signer[F[_], A, PubK[_], PrivK[_]] {

  def sign(unsigned: Array[Byte], secretKey: PrivK[A]): F[CryptoSignature[A]]

  final def verifyV(raw: Array[Byte], signature: CryptoSignature[A], publicKey: PubK[A])(
      implicit F: Functor[F]
  ): F[VerificationStatus] = F.map(verify(raw, signature, publicKey))(c => if (c) Verified else VerificationFailed)

  def verify(raw: Array[Byte], signature: CryptoSignature[A], publicKey: PubK[A]): F[Boolean]

}

trait CertificateSigner[F[_], A, PubK[_], PrivK[_], Cert[_]] extends Signer[F, A, PubK, PrivK] {
  def verifyCert(raw: Array[Byte], signature: CryptoSignature[A], cert: Cert[A]): F[Boolean]
}

trait IdSigner[A, PrivK[_], PubK[_], KP[_]] extends Signer[Id, A, PrivK, PubK]
