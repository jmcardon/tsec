package tsec.messagedigests.instances

import java.security.MessageDigest
import tsec.messagedigests.core.PureHasher

case class MD5(array: Array[Byte])

object MD5 extends DeriveHashTag[MD5]("MD5"){
  implicit lazy val jPureHasher: PureHasher[MessageDigest, MD5] =
    pureJavaHasher[MD5](_.array, MD5.apply)
}
