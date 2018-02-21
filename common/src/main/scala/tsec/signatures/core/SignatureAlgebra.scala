package tsec.signatures.core

import cats.effect.Sync

trait SignatureAlgebra[A, PubK[_], PrivK[_], KP[_], S[_[_]]] {

  def generateKeyPair[F[_]](implicit F: Sync[F], S: S[F]): F[KP[A]]

  def sign[F[_]](
      unsigned: Array[Byte],
      secretKey: PrivK[A]
  )(implicit F: Sync[F], S: S[F]): F[CryptoSignature[A]]

  def verify[F[_]](
      raw: Array[Byte],
      signature: CryptoSignature[A],
      publicKey: PubK[A],
  )(implicit F: Sync[F], S: S[F]): F[Boolean]

}
