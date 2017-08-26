package tsec.signature.instance

import java.security.cert.Certificate
import java.security.{PrivateKey, PublicKey, Signature}

import cats.Monad
import cats.effect.{Async, IO}
import com.softwaremill.tagging.@@
import tsec.signature.core._

sealed abstract class JCASigInterpreter[F[_], A](implicit M: Async[F], signatureAlgorithm: SignatureAlgorithm[A])
    extends SignatureAlgebra[F, A] {
  type S     = Signature
  type PubK  = PublicKey
  type PrivK = PrivateKey
  type Cert  = Certificate

  def genSignatureInstance: F[Signature] = M.delay(Signature.getInstance(signatureAlgorithm.algorithm))

  def initSign(p: SigPrivateKey[@@[PrivateKey, A]], instance: Signature): F[Unit] = M.delay(instance.initSign(p.key))

  def initVerifyK(p: SigPublicKey[@@[PublicKey, A]], instance: Signature): F[Unit] = M.delay(instance.initVerify(p.key))

  def initVerifyC(c: SigCertificate[@@[Certificate, A]], instance: Signature): F[Unit] =
    M.delay(instance.initVerify(c.certificate))

  def loadBytes(bytes: Array[Byte], instance: Signature): F[Unit] = M.delay(M.delay(instance.update(bytes)))

  def sign(instance: Signature): F[Array[Byte]] = M.delay(instance.sign())

  def verify(sig: Array[Byte], instance: Signature): F[Boolean] = M.delay(instance.verify(sig))
}

object JCASigInterpreter {

  def apply[F[_]: Async, A: SignatureAlgorithm] = new JCASigInterpreter[F, A]() {}

  implicit def genSig[F[_]: Async, A: SignatureAlgorithm]: JCASigInterpreter[F, A] = apply[F,A]

}