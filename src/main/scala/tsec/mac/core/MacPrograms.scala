package tsec.mac.core

import cats.Monad
import cats.implicits._
import shapeless.{Generic, HNil, ::}

abstract class MacPrograms[F[_]: Monad, A, K[_]](algebra: MacAlgebra[F, A, K],
  gen: MacPrograms.MacAux[A, Array[Byte]::HNil]) {

  def sign(content: Array[Byte], key: MacSigningKey[K[A]]): F[A] = {
    algebra.sign(content, key).map(f => gen.from(f::HNil))
  }

}

object MacPrograms {
  type MacAux[A, B] = Generic[A]{
    type Repr = B
  }
}