package tsec.cipher.common.padding

import tsec.cipher.common._

abstract class WithPaddingTag[T](repr: String) {
  implicit val tag: Padding[T] = new Padding[T] {
    override lazy val algorithm: String = repr
  }
}
