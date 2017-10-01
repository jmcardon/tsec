package tsec.messagedigests.instances

case class SHA512(array: Array[Byte])

object SHA512 extends DeriveHashTag[SHA512]("SHA-512")
