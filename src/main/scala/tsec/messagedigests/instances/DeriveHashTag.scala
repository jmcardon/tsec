package tsec.messagedigests.instances

import tsec.messagedigests.core.DigestTag

protected[instances] abstract class DeriveHashTag[T](repr: String){
  implicit lazy val hashTag: DigestTag[T] = new DigestTag[T] {
    override lazy val algorithm =  repr
  }
}
