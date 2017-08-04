package fucc.all.encryption.messagedigests.core

import java.security.MessageDigest

import com.softwaremill.tagging._

trait PureHasher[C]{
  def tagged(implicit hashTag: HashTag[C]): TaggedHasher[C] = MessageDigest.getInstance(hashTag.algorithm).taggedWith[C]
  def bytes(data: C): Array[Byte]
  def fromHashedBytes(array: Array[Byte]): C
  def hashToBytes(toHash: Array[Byte])(implicit hashTag: HashTag[C]): Array[Byte] = tagged.digest(toHash)
  def hash(toHash: Array[Byte])(implicit hashTag: HashTag[C]): C = fromHashedBytes(hashToBytes(toHash))
}
