package tsec.signature.core

trait SignatureAlgebra[F[_], A] {
  type S
  type PubK
  type PrivK
  type Cert

  def genSignatureInstance: F[S]

  def initSign(instance: S, p: PrivK): F[Unit]

  def initVerifyK(instance: S, p: PubK): F[Unit]

  def initVerifyC(instance: S, c: Cert): F[Unit]

  def loadBytes(bytes: Array[Byte], instance: S): F[Unit]

  def sign(instance: S): F[Array[Byte]]

  def verify(sig: Array[Byte], instance: S): F[Boolean]
}

object SignatureAlgebra {
  type Aux[F[_], A, PbK, PrK, C] = SignatureAlgebra[F, A] {
    type PubK  = PbK
    type PrivK = PrK
    type Cert  = C
  }
}
