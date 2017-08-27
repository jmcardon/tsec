package tsec.signature.core

import com.softwaremill.tagging.@@

trait SignatureAlgebra[F[_], A] {
  type S
  type PubK
  type PrivK
  type Cert

  def genSignatureInstance: F[S]

  def initSign(instance: S, p: SigPrivateKey[PrivK @@ A]): F[Unit]

  def initVerifyK(instance: S, p: SigPublicKey[PubK @@ A]): F[Unit]

  def initVerifyC(instance: S, c: SigCertificate[Cert @@ A]): F[Unit]

  def loadBytes(bytes: Array[Byte], instance: S): F[Unit]

  def sign(instance: S): F[Array[Byte]]

  def verify(sig: Array[Byte], instance: S): F[Boolean]
}
