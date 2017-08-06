package fucc.messagedigests.javahasher

import cats.data.NonEmptyList
import fucc.messagedigests.core.{CryptoPickler, HashTag}

sealed trait HashAlgorithm
case class SHA1(array: Array[Byte]) extends HashAlgorithm

object SHA1 extends DeriveHashTag[SHA1]("SHA-1")

case class MD5(array: Array[Byte]) extends HashAlgorithm

object MD5 extends DeriveHashTag[MD5]("MD5")

case class SHA256(array: Array[Byte]) extends HashAlgorithm

object SHA256 extends DeriveHashTag[SHA256]("SHA-256")

case class SHA512(array: Array[Byte]) extends HashAlgorithm

object SHA512 extends DeriveHashTag[SHA512]("SHA-512")

sealed abstract class DeriveHashTag[T: JPureHasher](repr: String){
  implicit val hashTag: HashTag[T] = HashTag.fromString[T](repr)
  implicit lazy val jHasher: JHasher[T] = JHasher[T]
  def hash[C: CryptoPickler]: (C) => T = jHasher.hash
  def combineAndHash[C: CryptoPickler]: (NonEmptyList[C]) => T = jHasher.combineAndHash[C]
  def hashCumulative[C : CryptoPickler]: (NonEmptyList[C]) => List[T] = jHasher.hashCumulative[C]
  def hashBatch[C: CryptoPickler]: (List[C]) => List[T] = jHasher.hashBatch[C]
}