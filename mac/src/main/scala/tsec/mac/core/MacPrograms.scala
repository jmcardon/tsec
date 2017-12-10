package tsec.mac.core

import cats.Monad
import cats.syntax.all._
import tsec.common.{ByteUtils}

abstract class MacPrograms[F[_]: Monad, A: MacTag, K[_]](val algebra: MacAlgebra[F, A, K]) {

  def sign(content: Array[Byte], key: K[A]): F[MAC[A]] =
    algebra.sign(content, key).map(MAC.apply[A])

  def verify(toSign: Array[Byte], signed: MAC[A], key: K[A]): F[Boolean] =
    algebra.sign(toSign, key).map(ByteUtils.constantTimeEquals(signed, _))

  def verifyArrays(toSign: Array[Byte], signed: Array[Byte], key: K[A]): F[Boolean] =
    algebra.sign(toSign, key).map(ByteUtils.constantTimeEquals(signed, _))

}