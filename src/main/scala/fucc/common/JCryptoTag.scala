package fucc.common

trait JCryptoTag[T] {
  val algorithm: String
}

object JCryptoTag {
  def fromString[T](repr: String): JCryptoTag[T] = new JCryptoTag[T] {
    override lazy val algorithm: String = repr
  }
}
