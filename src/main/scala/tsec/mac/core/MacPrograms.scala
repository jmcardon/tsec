package tsec.mac.core

import cats.Monad
import cats.syntax.all._
import shapeless.{::, Generic, HNil}
import tsec.core.ByteUtils

abstract class MacPrograms[F[_]: Monad, A, K[_]](val algebra: MacAlgebra[F, A, K])(implicit gen: ByteUtils.ByteAux[A]) {

  def sign(content: Array[Byte], key: K[A]): F[A] =
    algebra.sign(content, key).map(f => gen.from(f :: HNil))

  def verify(toVerify: Array[Byte], signed: A, key: K[A]): F[Boolean] = {
    val extracted = gen.to(signed).head
    algebra.sign(toVerify, key).map(signed => ByteUtils.constantTimeEquals(extracted, signed))
  }

}
