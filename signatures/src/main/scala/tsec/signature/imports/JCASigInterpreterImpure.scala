package tsec.signature.imports

import java.security.Signature
import cats.syntax.either._
import tsec.common.ErrorConstruct._
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
      .mapError(SignatureInitError.apply)

  def initSign(instance: Signature, p: SigPrivateKey[A]): SigErrorM[Unit] =
    Either.catchNonFatal(instance.initSign(SigPrivateKey.toJavaPrivateKey[A](p))).mapError(SignatureInitError.apply)

  def initVerifyK(instance: Signature, p: SigPublicKey[A]): SigErrorM[Unit] =
    Either.catchNonFatal(instance.initVerify(SigPublicKey.toJavaPublicKey[A](p))).mapError(SignatureInitError.apply)

  def initVerifyC(instance: Signature, c: SigCertificate[A]): SigErrorM[Unit] =
    Either
      .catchNonFatal(instance.initVerify(SigCertificate.toJavaCertificate[A](c)))
      .mapError(SignatureInitError.apply)

  def loadBytes(bytes: Array[Byte], instance: Signature): SigErrorM[Unit] =
    Either.catchNonFatal(instance.update(bytes)).mapError(GeneralSignatureError.apply)

  def sign(instance: Signature): SigErrorM[Array[Byte]] =
    Either.catchNonFatal(instance.sign()).mapError(GeneralSignatureError.apply)

  def verify(sig: Array[Byte], instance: Signature): SigErrorM[Boolean] =
    Either.catchNonFatal(instance.verify(sig)).mapError(SignatureVerificationError.apply)
}

object JCASigInterpreterImpure {

  implicit def genSig[A: SigAlgoTag]: JCASigInterpreterImpure[A] = new JCASigInterpreterImpure[A]() {}

}
