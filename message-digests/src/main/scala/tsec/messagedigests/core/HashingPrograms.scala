package tsec.messagedigests.core

import cats.data.{NonEmptyList, State}
import tsec.common.ByteEV
import tsec.messagedigests._

abstract class HashingPrograms[T](
    algebra: HashAlgebra[T]
)(implicit gen: ByteEV[T]) {

  def hash[C](toHash: C)(implicit cryptoPickler: CryptoPickler[C]): T =
    (algebra.hash _).andThen(gen.fromArray)(cryptoPickler.pickle(toHash))

  def hashBytes(bytes: Array[Byte]): T =
    gen.fromArray(algebra.hash(bytes))

  def hashToByteArray(bytes: Array[Byte]): Array[Byte] =
    algebra.hash(bytes)

  def hashBatch[C](toHash: List[C])(implicit cryptoPickler: CryptoPickler[C]): List[T] =
    algebra
      .hashBatch(
        algebra.lift(
          toHash
            .map(cryptoPickler.pickle)
        )
      )
      .map(gen.fromArray)

  def combineAndHash[C](toHash: NonEmptyList[C])(implicit cryptoPickler: CryptoPickler[C]): T =
    (algebra.hash _).andThen(gen.fromArray)(toHash.map(cryptoPickler.pickle).reduceLeft(_ ++ _))

  protected [tsec] def consumeAndLift(state: algebra.S): T =
    (algebra.consume _).andThen(gen.fromArray)(state)

  def hashCumulative[C](toHash: NonEmptyList[C])(implicit cryptoPickler: CryptoPickler[C]): List[T] = {
    def appendAndHash(newState: algebra.S): State[algebra.S, T] =
      State[algebra.S, T] { oldState =>
        val combined = algebra.monoid.combine(oldState, newState)
        (combined, consumeAndLift(combined))
      }

    val lifted: NonEmptyList[algebra.S] =
      toHash.map(cryptoPickler.pickle.andThen(algebra.liftS))
    lifted.tail
      .foldLeft(State.pure[algebra.S, List[T]](List(consumeAndLift(lifted.head)))) { (prev, right) =>
        for {
          arr <- prev
          n   <- appendAndHash(right)
        } yield n :: arr
      }
      .runA(lifted.head)
      .value
  }
}