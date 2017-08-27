package tsec.signature.core

import cats.Monad
import cats.implicits._
import com.softwaremill.tagging.@@
import shapeless.{Generic, HNil, ::}

case class SignerDSL[F[_]: Monad, A: SigAlgoTag](algebra: SignatureAlgebra[F, A])(implicit aux: SignerDSL.Aux[A]) {
  import algebra._

  def sign(content: Array[Byte], p: SigPrivateKey[PrivK @@ A]): F[A] =
    for {
      instance <- algebra.genSignatureInstance
      _        <- algebra.initSign(instance, p)
      _        <- algebra.loadBytes(content, instance)
      signed   <- algebra.sign(instance)
    } yield aux.from(signed::HNil)

  def verifyK(content: Array[Byte], k: SigPublicKey[PubK @@ A]): F[Boolean] = for {
    instance <- algebra.genSignatureInstance
    _ <- algebra.initVerifyK(instance, k)
    verified <- algebra.verify(content, instance)
  } yield verified

  def verifyC(content: Array[Byte], c: SigCertificate[Cert @@ A]): F[Boolean] = for {
    instance <- algebra.genSignatureInstance
    _ <- algebra.initVerifyC(instance, c)
    verified <- algebra.verify(content, instance)
  } yield verified

}

object SignerDSL {
  type Aux[A] = Generic[A] { type Repr = Array[Byte] :: HNil }
}