package tsec.signature.jca

import java.security.Signature

trait JCASigAlgebra[F[_], A, PubK[_], PrivK[_], Cert[_]] {
  type S = Signature

  def genSignatureInstance: F[S]

  def initSign(instance: S, p: PrivK[A]): F[Unit]

  def initVerifyK(instance: S, p: PubK[A]): F[Unit]

  def initVerifyC(instance: S, c: Cert[A]): F[Unit]

  def loadBytes(bytes: Array[Byte], instance: S): F[Unit]

  def sign(instance: S): F[Array[Byte]]

  def verify(sig: Array[Byte], instance: S): F[Boolean]
}
