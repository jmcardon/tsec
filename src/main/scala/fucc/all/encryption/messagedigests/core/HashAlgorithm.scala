package fucc.all.encryption.messagedigests.core

sealed trait HashAlgorithm
case class SHA1(array: Array[Byte]) extends HashAlgorithm

object SHA1 extends DeriveHashTag[SHA1]("SHA-1")

case class MD5(array: Array[Byte]) extends HashAlgorithm

object MD5 extends DeriveHashTag[MD5]("MD5")

case class SHA256(array: Array[Byte]) extends HashAlgorithm

object SHA256 extends DeriveHashTag[SHA256]("SHA-256")

case class SHA512(array: Array[Byte]) extends HashAlgorithm

object SHA512 extends DeriveHashTag[SHA512]("SHA-512")

sealed abstract class DeriveHashTag[T](repr: String){
  implicit val hashTag: HashTag[T] = HashTag.fromString[T](repr)
}