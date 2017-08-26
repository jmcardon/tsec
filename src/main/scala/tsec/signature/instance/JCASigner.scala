package tsec.signature.instance

import cats.effect.Async
import tsec.signature.core.{SignatureAlgorithm, SignerDSL}

sealed abstract class JCASigner[F[_]: Async, A: SignatureAlgorithm](
    algebra: JCASigInterpreter[F, A]
)(implicit aux: SignerDSL.Aux[A])
    extends SignerDSL[F, A](algebra)

object JCASigner {
  def apply[F[_]: Async, A: SignatureAlgorithm: SignerDSL.Aux](implicit s: JCASigInterpreter[F, A]) =
    new JCASigner[F, A](s) {}

  implicit def genSigner[F[_]: Async, A: SignatureAlgorithm: SignerDSL.Aux](
      implicit s: JCASigInterpreter[F, A]
  ): JCASigner[F, A] = apply[F, A]
}
