package tsec.cipher.common.padding

abstract class WithPaddingTag[T](repr: String) {
  implicit val tag: Padding[T] = new Padding[T] {
    override lazy val algorithm: String = repr
  }
}

class SymmetricPadding[T](val algorithm: String) extends Padding[T]

abstract class WithSymmetricPaddingTag[T](repr: String) extends SymmetricPadding[T](repr) {
  implicit val p: SymmetricPadding[T] = this
}
