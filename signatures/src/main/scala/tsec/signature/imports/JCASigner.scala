package tsec.signature.imports

import cats.instances.either._
import tsec.signature.core.{SigAlgoTag, SignaturePrograms}

sealed abstract case class JCASigner[A: SigAlgoTag](
    alg: JCASigInterpreterImpure[A]
)
    extends SignaturePrograms[SigErrorM, A] {

  type PubK  = SigPublicKey[A]
  type PrivK = SigPrivateKey[A]
  type Cert  = SigCertificate[A]
  val algebra: JCASigInterpreterImpure[A] = alg
}

object JCASigner {

  def apply[A: SigAlgoTag](implicit s: JCASigInterpreterImpure[A]): JCASigner[A] =
    new JCASigner[A](s) {}

  implicit def genSigner[A: SigAlgoTag](implicit s: JCASigInterpreterImpure[A]): JCASigner[A] = apply[A]

}
