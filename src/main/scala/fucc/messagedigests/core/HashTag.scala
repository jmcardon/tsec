package fucc.messagedigests.core

trait HashTag[T] {
  val algorithm: String
}

object HashTag {
  def fromString[T](repr: String): HashTag[T] = new HashTag[T] {
    override lazy val algorithm: String = repr
  }
}
