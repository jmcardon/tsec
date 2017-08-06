package fucc.messagedigests.core

import cats.data.{NonEmptyList, State}

abstract class HashingPrograms[K, T](algebra: HashAlgebra[T])(
    implicit val p: PureHasher[K, T]) {

  def hash[C](toHash: C)(implicit cryptoPickler: CryptoPickler[C]): T = {
    (algebra.hash _).andThen(p.fromHashedBytes)(cryptoPickler.pickle(toHash))
  }

  def hashBatch[C](toHash: List[C])(
      implicit cryptoPickler: CryptoPickler[C]): List[T] = {
    algebra
      .hashBatch(
        algebra.lift(
          toHash
            .map(cryptoPickler.pickle))
      )
      .map(p.fromHashedBytes)
  }

  def combineAndHash[C](toHash: NonEmptyList[C])(
      implicit cryptoPickler: CryptoPickler[C]): T = {
    (algebra.hash _).andThen(p.fromHashedBytes)(
      toHash.map(cryptoPickler.pickle).reduceLeft(_ ++ _))
  }

  def consumeAndLift(state: algebra.S): T = {
    (algebra.consume _).andThen(p.fromHashedBytes)(state)
  }

  def hashCumulative[C](toHash: NonEmptyList[C])(
      implicit cryptoPickler: CryptoPickler[C]): List[T] = {
    def appendAndHash(newState: algebra.S): State[algebra.S, T] =
      State[algebra.S, T] { oldState =>
        val combined = algebra.monoid.combine(oldState, newState)
        (combined, consumeAndLift(combined))
      }

    val lifted: NonEmptyList[algebra.S] =
      toHash.map(cryptoPickler.pickle.andThen(algebra.liftS))
    lifted.tail
      .foldLeft(
        State.pure[algebra.S, List[T]](List(consumeAndLift(lifted.head)))) {
        (prev, right) =>
          for {
            arr <- prev
            n <- appendAndHash(right)
          } yield n :: arr
      }
      .runA(lifted.head)
      .value
  }

}
