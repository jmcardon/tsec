package tsec.signature.core

import com.softwaremill.tagging.@@

trait SignatureAlgebra[F[_], A] {
  type S
  type PubK
  type PrivK
  type Cert

  def genSignatureInstance: F[S]

  def initSign(p: SigPrivateKey[PrivK @@ A], instance: S): F[Unit]

  def initVerifyK(p: SigPublicKey[PubK @@ A], instance: S): F[Unit]

  def initVerifyC(c: SigCertificate[Cert @@ A], instance: S): F[Unit]

  def loadBytes(bytes: Array[Byte], instance: S): F[Unit]

  def sign(instance: S): F[Array[Byte]]

  def verify(sig: Array[Byte], instance: S): F[Boolean]

}