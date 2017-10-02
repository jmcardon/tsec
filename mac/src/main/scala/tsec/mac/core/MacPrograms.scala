package tsec.mac.core

import cats.Monad
import cats.syntax.all._
import shapeless.HNil
import tsec.common.ByteUtils

abstract class MacPrograms[F[_]: Monad, A, K[_]](val algebra: MacAlgebra[F, A, K])(implicit gen: ByteUtils.ByteAux[A]) {

  def sign(content: Array[Byte], key: K[A]): F[A] =
    algebra.sign(content, key).map(f => gen.from(f :: HNil))

  def verify(toSign: Array[Byte], signed: A, key: K[A]): F[Boolean] =
    algebra.sign(toSign, key).map(ByteUtils.constantTimeEquals(gen.to(signed).head, _))

  def verifyArrays(toSign: Array[Byte], signed: Array[Byte], key: K[A]): F[Boolean] =
    algebra.sign(toSign, key).map(ByteUtils.constantTimeEquals(signed, _))

}
