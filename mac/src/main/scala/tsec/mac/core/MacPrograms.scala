package tsec.mac.core

import cats.Monad
import cats.syntax.all._
import tsec.common.{ByteEV, ByteUtils}

abstract class MacPrograms[F[_]: Monad, A, K[_]](val algebra: MacAlgebra[F, A, K])(implicit ev: ByteEV[A]) {

  def sign(content: Array[Byte], key: K[A]): F[A] =
    algebra.sign(content, key).map(ev.fromArray)

  def verify(toSign: Array[Byte], signed: A, key: K[A]): F[Boolean] =
    algebra.sign(toSign, key).map(ByteUtils.constantTimeEquals(ev.toArray(signed), _))

  def verifyArrays(toSign: Array[Byte], signed: Array[Byte], key: K[A]): F[Boolean] =
    algebra.sign(toSign, key).map(ByteUtils.constantTimeEquals(signed, _))

}
