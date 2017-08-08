package fucc.core

trait CryptoTag[T] {
  val algorithm: String
}

object CryptoTag {
  def fromString[T](repr: String): CryptoTag[T] = new CryptoTag[T] {
    override lazy val algorithm: String = repr
  }
}
