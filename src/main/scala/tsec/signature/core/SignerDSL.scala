package tsec.signature.core

import cats.Monad
import cats.implicits._
import com.softwaremill.tagging.@@

class SignerDSL[F[_]: Monad, A: SignatureAlgorithm](algebra: SignatureAlgebra[F, A]) {
  import algebra.{Cert, PrivK, PubK, S}

  def sign(p: SigPrivateKey[PrivK @@ A], content: Array[Byte]): F[Array[Byte]] =
    for {
      instance <- algebra.genSignatureInstance
      _        <- algebra.initSign(p, instance)
      _        <- algebra.loadBytes(content, instance)
      signed   <- algebra.sign(instance)
    } yield signed

  def verifyK(k: SigPublicKey[PubK @@ A], content: Array[Byte]): F[Boolean] = for {
    instance <- algebra.genSignatureInstance
    _ <- algebra.initVerifyK(k,instance)
    verified <- algebra.verify(content, instance)
  } yield verified

  def verifyC(c: SigCertificate[Cert @@ A], content: Array[Byte]) = for {
    instance <- algebra.genSignatureInstance
    _ <- algebra.initVerifyC(c, instance)
    verified <- algebra.verify(content, instance)
  } yield verified

}
