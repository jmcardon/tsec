package tsec.signature.core

import cats.Monad
import cats.implicits._

abstract class SignaturePrograms[F[_]: Monad, A: SigAlgoTag] {
  type PubK
  type PrivK
  type Cert
  val algebra: SignatureAlgebra.Aux[F, A, PubK, PrivK, Cert]

  def sign(content: Array[Byte], p: PrivK): F[CryptoSignature[A]] =
    for {
      instance <- algebra.genSignatureInstance
      _        <- algebra.initSign(instance, p)
      _        <- algebra.loadBytes(content, instance)
      signed   <- algebra.sign(instance)
    } yield CryptoSignature[A](signed)

  def verifyK(toSign: Array[Byte], signed: Array[Byte], k: PubK): F[Boolean] =
    for {
      instance <- algebra.genSignatureInstance
      _        <- algebra.initVerifyK(instance, k)
      _        <- algebra.loadBytes(toSign, instance)
      verified <- algebra.verify(signed, instance)
    } yield verified

  def verifyKI(toSign: Array[Byte], signed: CryptoSignature[A], k: PubK): F[Boolean] = verifyK(toSign, signed, k)

  def verifyC(toSign: Array[Byte], signed: Array[Byte], c: Cert): F[Boolean] =
    for {
      instance <- algebra.genSignatureInstance
      _        <- algebra.initVerifyC(instance, c)
      _        <- algebra.loadBytes(toSign, instance)
      verified <- algebra.verify(signed, instance)
    } yield verified

  def verifyCI(toSign: Array[Byte], signed: CryptoSignature[A], c: Cert): F[Boolean] = verifyC(toSign, signed, c)

}

object SignaturePrograms {
  type Aux[F[_], A, PbK, PrK, C] = SignaturePrograms[F, A] {
    type PubK  = PbK
    type PrivK = PrK
    type Cert  = C
  }
}
