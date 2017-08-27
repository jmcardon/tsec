package tsec.signature.instance

import java.security.cert.Certificate
import java.security.{PrivateKey, PublicKey, Signature}

import cats.effect.{Async, Sync}
import tsec.signature.core.{SigAlgoTag, SignatureAlgebra, SignerDSL}

sealed abstract class JCASigner[F[_]: Sync, A: SigAlgoTag](
    algebra: JCASigInterpreter[F, A]
)(implicit aux: SignerDSL.Aux[A])
    extends SignerDSL[F, A](algebra)

object JCASigner {
  type SigAlgAux[F[_],A] = SignerDSL[F, A]{
    type S = Signature
    type PrivK = PrivateKey
    type PubK = PublicKey
    type Cert = Certificate
  }

  def apply[F[_]: Sync, A: SigAlgoTag: SignerDSL.Aux](implicit s: JCASigInterpreter[F, A]) =
    new JCASigner[F, A](s) {}

  implicit def genSigner[F[_]: Sync, A: SigAlgoTag: SignerDSL.Aux](
      implicit s: JCASigInterpreter[F, A]
  ): JCASigner[F, A] = apply[F, A]
}
