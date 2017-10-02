package tsec.signature.imports

import java.security.Signature

import cats.syntax.either._
import tsec.core.ErrorConstruct._
import tsec.signature.core.{SigAlgoTag, SignatureAlgebra}

sealed abstract class JCASigInterpreterImpure[A](implicit signatureAlgorithm: SigAlgoTag[A])
    extends SignatureAlgebra[SigErrorM, A] {
  type S     = Signature
  type PubK  = SigPublicKey[A]
  type PrivK = SigPrivateKey[A]
  type Cert  = SigCertificate[A]

  def genSignatureInstance: SigErrorM[Signature] =
    Either
      .catchNonFatal(Signature.getInstance(signatureAlgorithm.algorithm))
      .mapError[SignatureInitError]

  def initSign(instance: Signature, p: SigPrivateKey[A]): SigErrorM[Unit] =
    Either.catchNonFatal(instance.initSign(p.key)).mapError[SignatureInitError]

  def initVerifyK(instance: Signature, p: SigPublicKey[A]): SigErrorM[Unit] =
    Either.catchNonFatal(instance.initVerify(p.key)).mapError[SignatureInitError]

  def initVerifyC(instance: Signature, c: SigCertificate[A]): SigErrorM[Unit] =
    Either.catchNonFatal(instance.initVerify(c.certificate)).mapError[SignatureInitError]

  def loadBytes(bytes: Array[Byte], instance: Signature): SigErrorM[Unit] =
    Either.catchNonFatal(instance.update(bytes)).mapError[GeneralSignatureError]

  def sign(instance: Signature): SigErrorM[Array[Byte]] =
    Either.catchNonFatal(instance.sign()).mapError[GeneralSignatureError]

  def verify(sig: Array[Byte], instance: Signature): SigErrorM[Boolean] =
    Either.catchNonFatal(instance.verify(sig)).mapError[SignatureVerificationError]
}

object JCASigInterpreterImpure {

  implicit def genSig[A: SigAlgoTag]: JCASigInterpreterImpure[A] = new JCASigInterpreterImpure[A]() {}

}
