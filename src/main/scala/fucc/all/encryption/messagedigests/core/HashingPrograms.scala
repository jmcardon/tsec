package fucc.all.encryption.messagedigests.core

import cats.data.{NonEmptyList, State}

abstract class HashingPrograms[K, T](
    algebra: HashAlgebra[T])(implicit val p: PureHasher[K,T]) {

  def hash[C](toHash: C)(implicit cryptoPickler: CryptoPickler[C]): T = {
    (algebra.hash _).andThen(p.fromHashedBytes)(cryptoPickler.pickler(toHash))
  }

  def hashCombine[C](toHash: NonEmptyList[C])(
      implicit cryptoPickler: CryptoPickler[C]): T = {
    (algebra.hash _).andThen(p.fromHashedBytes)(toHash.map(cryptoPickler.pickler).reduceLeft(_ ++ _))
  }

  def consumeAndLift(state: algebra.S): T = {
    (algebra.consume _).andThen(p.fromHashedBytes)(state)
  }

  def hashCumulative[C](toHash: NonEmptyList[C])(implicit cryptoPickler: CryptoPickler[C]): List[Array[Byte]] = {
    def appendAndHash(newState: algebra.S): State[algebra.S, Array[Byte]] = State[algebra.S, Array[Byte]]{
      oldState =>
        val combined = algebra.monoid.combine(oldState, newState)
        (combined, algebra.consume(combined))
    }

    val lifted: NonEmptyList[algebra.S] = toHash.map(cryptoPickler.pickler.andThen(algebra.liftS))
    lifted.tail.foldLeft(State.pure[algebra.S, List[Array[Byte]]](Nil)){
      (prev, right) =>
        for{
          arr <- prev
          n <- appendAndHash(right)
        } yield n :: arr
    }.runA(lifted.head).value
  }

}
