package tsec

import cats.data.{OptionT}

package object auth{

  trait BackingStore[F[_], I, V] {
    def put(id: I, elem: V):  F[Int]

    def get(id: I): OptionT[F, V]

    def update(v: V): F[Int]

    def delete(id: I): F[Int]
  }

}
