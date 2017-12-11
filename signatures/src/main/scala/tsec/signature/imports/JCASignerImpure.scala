package tsec.signature.imports

import cats.instances.either._
import tsec.signature.core.{CryptoSignature, SigAlgoTag, SignaturePrograms}

sealed abstract case class JCASignerImpure[A: SigAlgoTag](
    alg: JCASigInterpreterImpure[A]
) extends SignaturePrograms[SigErrorM, A] {

  type PubK  = SigPublicKey[A]
  type PrivK = SigPrivateKey[A]
  type Cert  = SigCertificate[A]
  val algebra: JCASigInterpreterImpure[A] = alg
}

object JCASignerImpure {

  def apply[A: SigAlgoTag](implicit s: JCASigInterpreterImpure[A]): JCASignerImpure[A] =
    new JCASignerImpure[A](s) {}

  implicit def genSigner[A: SigAlgoTag](implicit s: JCASigInterpreterImpure[A]): JCASignerImpure[A] = apply[A]

  def sign[A: SigAlgoTag](content: Array[Byte], p: SigPrivateKey[A])(
      implicit js: JCASignerImpure[A]
  ): SigErrorM[CryptoSignature[A]] = js.sign(content, p)

  def verifyK[A: SigAlgoTag](toSign: Array[Byte], signed: Array[Byte], k: SigPublicKey[A])(
      implicit js: JCASignerImpure[A]
  ): SigErrorM[Boolean] =
    js.verifyK(toSign, signed, k)

  def verifyKI[A: SigAlgoTag](toSign: Array[Byte], signed: CryptoSignature[A], k: SigPublicKey[A])(
      implicit js: JCASignerImpure[A]
  ): SigErrorM[Boolean] = js.verifyKI(toSign, signed, k)

  def verifyC[A: SigAlgoTag](toSign: Array[Byte], signed: Array[Byte], c: SigCertificate[A])(
      implicit js: JCASignerImpure[A]
  ): SigErrorM[Boolean] = js.verifyC(toSign, signed, c)

  def verifyCI[A: SigAlgoTag](toSign: Array[Byte], signed: CryptoSignature[A], c: SigCertificate[A])(
      implicit js: JCASignerImpure[A]
  ): SigErrorM[Boolean] = js.verifyCI(toSign, signed, c)

}
