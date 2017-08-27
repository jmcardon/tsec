package tsec.signature.instance

import cats.effect.{Async, Sync}
import tsec.core.ByteUtils.ByteAux
import tsec.signature.core.{SigAlgoTag, SignatureAlgebra, SignerDSL}

sealed abstract class JCASigner[F[_]: Sync, A: SigAlgoTag](
    algebra: JCASigInterpreter[F, A]
)(implicit aux: ByteAux[A])
    extends SignerDSL[F, A](algebra)

object JCASigner {

  def apply[F[_]: Sync, A: SigAlgoTag: ByteAux](implicit s: JCASigInterpreter[F, A]) =
    new JCASigner[F, A](s) {}

  implicit def genSigner[F[_]: Sync, A: SigAlgoTag: ByteAux](
      implicit s: JCASigInterpreter[F, A]
  ): JCASigner[F, A] = apply[F, A]
}
