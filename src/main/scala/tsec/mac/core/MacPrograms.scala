package tsec.mac.core

import cats.Monad
import cats.implicits._
import shapeless.{::, Generic, HNil}
import tsec.core.ByteUtils

abstract class MacPrograms[F[_]: Monad, A, K[_]](val algebra: MacAlgebra[F, A, K])(implicit gen: ByteUtils.ByteAux[A]) {

  def sign(content: Array[Byte], key: MacSigningKey[K[A]]): F[A] =
    algebra.sign(content, key).map(f => gen.from(f :: HNil))

}
