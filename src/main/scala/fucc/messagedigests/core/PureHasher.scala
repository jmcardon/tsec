package fucc.messagedigests.core

trait PureHasher[K, C]{
  def tagged(implicit hashTag: HashTag[C]): TaggedHasher[K, C]
  def bytes(data: C): Array[Byte]
  def fromHashedBytes(array: Array[Byte]): C
  def hashToBytes(toHash: Array[Byte])(implicit hashTag: HashTag[C]): Array[Byte]
  def hash(toHash: Array[Byte])(implicit hashTag: HashTag[C]): C = fromHashedBytes(hashToBytes(toHash))
}
