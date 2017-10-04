package tsec.messagedigests.imports

import tsec.messagedigests.core.DigestTag

protected[imports] abstract class DeriveHashTag[T](repr: String) extends DigestTag[T] { //Todo: Remove redundant class?
  override lazy val algorithm: String = repr
}
