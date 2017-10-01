package tsec.signature.instance

import tsec.core.ByteUtils.ByteAux
import tsec.signature.core.{SigAlgoTag, SignerPrograms}
import cats.instances.either._

sealed abstract case class JCASigner[A: SigAlgoTag](
    alg: JCASigInterpreterImpure[A]
)(implicit aux: ByteAux[A])
    extends SignerPrograms[SigErrorM, A] {

  type PubK  = SigPublicKey[A]
  type PrivK = SigPrivateKey[A]
  type Cert  = SigCertificate[A]
  val algebra: JCASigInterpreterImpure[A] = alg
}

object JCASigner {

  def apply[A: SigAlgoTag: ByteAux](implicit s: JCASigInterpreterImpure[A]): JCASigner[A] =
    new JCASigner[A](s) {}

  implicit def genSigner[A: SigAlgoTag: ByteAux](implicit s: JCASigInterpreterImpure[A]): JCASigner[A] = apply[A]

}
