package fucc.all.encryption.messagedigests.core

import cats._
import cats.data.NonEmptyList
import cats.implicits._

abstract class HashingPrograms[F[_]: Monad, T <: HashAlgorithm](
    algebra: DigestAlgebra[F, T])(implicit val p: PureHasher[T]) {

  def hash[C](toHash: C)(implicit cryptoPickler: CryptoPickler[C]): F[T] = {
    algebra
      .hash(cryptoPickler.pickler(toHash))
      .map(p.fromHashedBytes)
  }

  def hashCombine[C](toHash: NonEmptyList[C])(
      implicit cryptoPickler: CryptoPickler[C]): F[T] = {
    algebra
      .hash(toHash.map(cryptoPickler.pickler).reduceLeft(_ ++ _))
      .map(p.fromHashedBytes)
  }

  def hashCumulative[C](toHash: NonEmptyList[C])(implicit cryptoPickler: CryptoPickler[C]): F[T] = {
    val lifted: NonEmptyList[algebra.S] = toHash.map(cryptoPickler.pickler.andThen(algebra.liftS))
    lifted.tail.foldLeft(algebra.consume(lifted.head).map(l => (p.fromHashedBytes(l), lifted.head))){
      (accumulator, right) =>
        for {
          a <- accumulator
          combined = algebra.monoid.combine(a._2,right)
          n <- algebra.consume(combined)
        } yield (p.fromHashedBytes(n), combined)
    }.map(_._1)
  }
}
