package tsec.messagedigests.imports

import tsec.messagedigests.core.DigestTag

protected[imports] abstract class DeriveHashTag[T](repr: String) {
  implicit lazy val hashTag: DigestTag[T] = new DigestTag[T] {
    override lazy val algorithm = repr
  }
}
