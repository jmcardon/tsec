package fucc.messagedigests.core

import fucc.common.JCryptoTag

trait PureHasher[K, C]{
  def tagged(implicit hashTag: JCryptoTag[C]): TaggedHasher[K, C]
  def bytes(data: C): Array[Byte]
  def fromHashedBytes(array: Array[Byte]): C
  def hashToBytes(toHash: Array[Byte])(implicit hashTag: JCryptoTag[C]): Array[Byte]
  def hash(toHash: Array[Byte])(implicit hashTag: JCryptoTag[C]): C = fromHashedBytes(hashToBytes(toHash))
}
