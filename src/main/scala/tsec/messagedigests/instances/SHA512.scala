package tsec.messagedigests.instances

import java.security.MessageDigest

import tsec.messagedigests.core.PureHasher

case class SHA512(array: Array[Byte])

object SHA512 extends DeriveHashTag[SHA512]("SHA-512"){
  implicit lazy val jPureHasher: PureHasher[MessageDigest, SHA512] =
    pureJavaHasher[SHA512](_.array, SHA512.apply)
}
