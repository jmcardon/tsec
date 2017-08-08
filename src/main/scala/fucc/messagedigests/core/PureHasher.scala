package fucc.messagedigests.core

import fucc.core.CryptoTag

trait PureHasher[K, C]{
  def tagged(implicit hashTag: CryptoTag[C]): TaggedHasher[K, C]
  def bytes(data: C): Array[Byte]
  def fromHashedBytes(array: Array[Byte]): C
  def hashToBytes(toHash: Array[Byte])(implicit hashTag: CryptoTag[C]): Array[Byte]
  def hash(toHash: Array[Byte])(implicit hashTag: CryptoTag[C]): C = fromHashedBytes(hashToBytes(toHash))
}
