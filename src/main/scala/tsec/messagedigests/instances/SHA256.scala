package tsec.messagedigests.instances

import java.security.MessageDigest

import tsec.messagedigests.core.PureHasher

case class SHA256(array: Array[Byte])

object SHA256 extends DeriveHashTag[SHA256]("SHA-256"){
  implicit lazy val jPureHasher: PureHasher[MessageDigest, SHA256] =
    pureJavaHasher[SHA256](_.array, SHA256.apply)
}
