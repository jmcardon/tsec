package tsec.signature.imports

import cats.effect.Sync
import tsec.core.ByteUtils.ByteAux
import tsec.signature.core.{SigAlgoTag, SignerPrograms}

sealed abstract case class JCASignerPure[F[_]: Sync, A: SigAlgoTag](
    alg: JCASigInterpreterPure[F, A]
)(implicit aux: ByteAux[A])
    extends SignerPrograms[F, A] {

  type PubK  = SigPublicKey[A]
  type PrivK = SigPrivateKey[A]
  type Cert  = SigCertificate[A]
  val algebra: JCASigInterpreterPure[F, A] = alg
}

object JCASignerPure {

  def apply[F[_]: Sync, A: SigAlgoTag: ByteAux](implicit s: JCASigInterpreterPure[F, A]) =
    new JCASignerPure[F, A](s) {}

  implicit def genSigner[F[_]: Sync, A: SigAlgoTag: ByteAux](
      implicit s: JCASigInterpreterPure[F, A]
  ): JCASignerPure[F, A] = apply[F, A]

}
