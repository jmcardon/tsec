package tsec.messagedigests.imports

case class SHA256(array: Array[Byte])

object SHA256 extends DeriveHashTag[SHA256]("SHA-256")
