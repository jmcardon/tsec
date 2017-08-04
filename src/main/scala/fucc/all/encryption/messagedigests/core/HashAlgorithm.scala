package fucc.all.encryption.messagedigests.core

sealed trait HashAlgorithm
case class SHA1(array: Array[Byte]) extends HashAlgorithm

object SHA1 extends DeriveHashTag[SHA1](_.array, new SHA1(_), "SHA-1")

case class MD5(array: Array[Byte]) extends HashAlgorithm

object MD5 extends DeriveHashTag[MD5](_.array, new MD5(_), "MD5")

case class SHA256(array: Array[Byte]) extends HashAlgorithm

object SHA256 extends DeriveHashTag[SHA256](_.array, new SHA256(_),"SHA-256")

case class SHA512(array: Array[Byte]) extends HashAlgorithm

object SHA512 extends DeriveHashTag[SHA512](_.array, new SHA512(_), "SHA-512")

sealed abstract class DeriveHashTag[T](extract: T => Array[Byte], build: Array[Byte] => T, repr: String){
  implicit val hashTag: HashTag[T] = HashTag.fromString[T](repr)
  implicit lazy val pureHasher = new PureHasher[T] {
    def bytes(data: T): Array[Byte] = extract(data)
    def fromHashedBytes(array: Array[Byte]): T = build(array)
  }
}