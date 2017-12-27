package tsec.cipher.common.padding

abstract class WithPaddingTag[T](repr: String) {
  implicit val tag: Padding[T] = new Padding[T] {
    override lazy val algorithm: String = repr
  }
}
