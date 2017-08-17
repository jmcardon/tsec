package tsec.messagedigests.instances

import java.security.MessageDigest

import tsec.messagedigests.core.PureHasher

case class SHA1(array: Array[Byte])

object SHA1 extends DeriveHashTag[SHA1]("SHA-1") {
  override implicit lazy val jPureHasher: PureHasher[MessageDigest, SHA1] =
    pureJavaHasher[SHA1]

  override implicit lazy val jHasher: JHasher[SHA1] = JHasher[SHA1]
}
