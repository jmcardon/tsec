package tsec.common

trait CryptoTag[T] {
  def algorithm: String
}

object CryptoTag {
  def fromString[T](repr: String): CryptoTag[T] = new CryptoTag[T] {
    override lazy val algorithm: String = repr
  }
}

abstract class WithCryptoTag[T](repr: String) {
  implicit val tag: CryptoTag[T] = CryptoTag.fromString[T](repr)
}
