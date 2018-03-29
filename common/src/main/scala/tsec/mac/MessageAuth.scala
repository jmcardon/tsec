package tsec.mac

import cats.Functor
import tsec.common.{VerificationFailed, VerificationStatus, Verified}

trait MessageAuth[F[_], A, K[_]] {

  def sign(in: Array[Byte], key: K[A]): F[MAC[A]]

  def verifyBool(in: Array[Byte], hashed: MAC[A], key: K[A]): F[Boolean]

  def verify(in: Array[Byte], hashed: MAC[A], key: K[A])(implicit F: Functor[F]): F[VerificationStatus] =
    F.map(verifyBool(in, hashed, key))(c => if (c) Verified else VerificationFailed)

}
