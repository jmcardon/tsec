package tsec.signature.jca

import java.security.Signature

import cats.effect.Sync

abstract class JCASigInterpreter[F[_], A](algorithm: String)(implicit M: Sync[F])
    extends JCASigAlgebra[F, A, SigPublicKey, SigPrivateKey, SigCertificate] {

  def genSignatureInstance: F[Signature] = M.delay(Signature.getInstance(algorithm))

  def initSign(instance: Signature, p: SigPrivateKey[A]): F[Unit] =
    M.delay(instance.initSign(SigPrivateKey.toJavaPrivateKey[A](p)))

  def initVerifyK(instance: Signature, p: SigPublicKey[A]): F[Unit] =
    M.delay(instance.initVerify(SigPublicKey.toJavaPublicKey[A](p)))

  def initVerifyC(instance: Signature, c: SigCertificate[A]): F[Unit] =
    M.delay(instance.initVerify(SigCertificate.toJavaCertificate[A](c)))

  def loadBytes(bytes: Array[Byte], instance: Signature): F[Unit] = M.delay(instance.update(bytes))

  def sign(instance: Signature): F[Array[Byte]] = M.delay(instance.sign())

  def verify(sig: Array[Byte], instance: Signature): F[Boolean] = M.delay(instance.verify(sig))

}
