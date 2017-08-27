package tsec.messagedigests.instances

import tsec.core.CryptoTag

protected[instances] abstract class DeriveHashTag[T](repr: String){
  implicit lazy val hashTag: CryptoTag[T] = CryptoTag.fromString[T](repr)
  implicit def jPureHasher: JPureHasher[T]
  implicit def jHasher: JHasher[T]
}
