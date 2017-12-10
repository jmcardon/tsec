package tsec.messagedigests.imports

import tsec.messagedigests.core.DigestTag

protected[imports] abstract class WithHashTag[T](repr: String) extends DigestTag[T] {
  override lazy val algorithm: String = repr
  implicit val tag: DigestTag[T]      = this
}
