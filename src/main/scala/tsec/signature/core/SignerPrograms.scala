package tsec.signature.core

import cats.Monad
import cats.implicits._
import shapeless.{::, Generic, HNil}
import tsec.core.ByteUtils.ByteAux

abstract class SignerPrograms[F[_]: Monad, A: SigAlgoTag](implicit aux: ByteAux[A]) {
  type PubK
  type PrivK
  type Cert
  val algebra: SignatureAlgebra.Aux[F, A, PubK, PrivK, Cert]

  def sign(content: Array[Byte], p: PrivK): F[A] =
    for {
      instance <- algebra.genSignatureInstance
      _        <- algebra.initSign(instance, p)
      _        <- algebra.loadBytes(content, instance)
      signed   <- algebra.sign(instance)
    } yield aux.from(signed :: HNil)

  def verifyK(content: Array[Byte], k: PubK): F[Boolean] =
    for {
      instance <- algebra.genSignatureInstance
      _        <- algebra.initVerifyK(instance, k)
      verified <- algebra.verify(content, instance)
    } yield verified

  def verifyKI(signed: A, k: PubK): F[Boolean] = verifyK(aux.to(signed).head,k)

  def verifyC(content: Array[Byte], c: Cert): F[Boolean] =
    for {
      instance <- algebra.genSignatureInstance
      _        <- algebra.initVerifyC(instance, c)
      verified <- algebra.verify(content, instance)
    } yield verified

  def verifyCI(signed: A, c: Cert): F[Boolean] = verifyC(aux.to(signed).head, c)

}

object SignerPrograms {
  type Aux[F[_], A, PbK, PrK, C] = SignerPrograms[F, A] {
    type PubK  = PbK
    type PrivK = PrK
    type Cert  = C
  }
}
