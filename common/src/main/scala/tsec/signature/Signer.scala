package tsec.signature

import cats.Id

trait Signer[F[_], A, PubK[_], PrivK[_]] {

  def sign(unsigned: Array[Byte], secretKey: PrivK[A]): F[CryptoSignature[A]]

  def verify(raw: Array[Byte], signature: CryptoSignature[A], publicKey: PubK[A]): F[Boolean]

}

trait CertificateSigner[F[_], A, PubK[_], PrivK[_], Cert[_]] extends Signer[F, A, PubK, PrivK] {
  def verifyCert(raw: Array[Byte], signature: CryptoSignature[A], cert: Cert[A]): F[Boolean]
}

trait IdSigner[A, PrivK[_], PubK[_], KP[_]] extends Signer[Id, A, PrivK, PubK]
