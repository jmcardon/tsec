package tsec.messagedigests.instances

case class MD5(array: Array[Byte])

object MD5 extends DeriveHashTag[MD5]("MD5")
