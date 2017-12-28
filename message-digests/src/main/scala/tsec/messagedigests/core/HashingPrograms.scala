package tsec.messagedigests.core

import cats.data.NonEmptyList
import tsec.messagedigests._

abstract class HashingPrograms[T: DigestTag](
    algebra: HashAlgebra[T]
) {

  def hash[C](toHash: C)(implicit cryptoPickler: CryptoPickler[C]): CryptoHash[T] =
    (algebra.hash _).andThen(CryptoHash[T])(cryptoPickler.pickle(toHash))

  def hashBytes(bytes: Array[Byte]): CryptoHash[T] =
    CryptoHash[T](algebra.hash(bytes))

  def hashToByteArray(bytes: Array[Byte]): Array[Byte] =
    algebra.hash(bytes)

  def combineAndHash[C](toHash: NonEmptyList[C])(implicit cryptoPickler: CryptoPickler[C]): CryptoHash[T] =
    (algebra.hash _).andThen(CryptoHash[T])(toHash.map(cryptoPickler.pickle).reduceLeft(_ ++ _))
}
