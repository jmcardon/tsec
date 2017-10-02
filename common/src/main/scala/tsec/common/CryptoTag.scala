package tsec.common

import shapeless.tag
import shapeless.tag.@@

trait CryptoTag[T] {
  def algorithm: String
}

object CryptoTag {
  def fromString[T](repr: String): CryptoTag[T] = new CryptoTag[T] {
    override lazy val algorithm: String = repr
  }

  def fromStringTagged[T, K](repr: String): CryptoTag[T] @@ K = tag[K](fromString[T](repr))
}

abstract class WithCryptoTag[T](repr: String) {
  implicit val tag: CryptoTag[T] = CryptoTag.fromString[T](repr)
}
