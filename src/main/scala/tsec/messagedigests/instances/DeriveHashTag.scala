package tsec.messagedigests.instances

import cats.data.NonEmptyList

import tsec.core.CryptoTag
import tsec.messagedigests.core.CryptoPickler

protected[instances] abstract class DeriveHashTag[T](repr: String) {
  implicit val jPureHasher: JPureHasher[T]
  implicit val hashTag: CryptoTag[T]                                 = CryptoTag.fromString[T](repr)
  implicit lazy val jHasher: JHasher[T]                              = JHasher[T]
  def hash[C: CryptoPickler]: (C) => T                               = jHasher.hash
  def combineAndHash[C: CryptoPickler]: (NonEmptyList[C]) => T       = jHasher.combineAndHash[C]
  def hashCumulative[C: CryptoPickler]: (NonEmptyList[C]) => List[T] = jHasher.hashCumulative[C]
  def hashBatch[C: CryptoPickler]: (List[C]) => List[T]              = jHasher.hashBatch[C]
}