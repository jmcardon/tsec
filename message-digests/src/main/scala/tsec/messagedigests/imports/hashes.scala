package tsec.messagedigests.imports

sealed trait MD5

object MD5 extends WithHashTag[MD5]("MD5")

sealed trait SHA1

object SHA1 extends WithHashTag[SHA1]("SHA-1")

sealed trait SHA256

object SHA256 extends WithHashTag[SHA256]("SHA-256")

sealed trait SHA512

object SHA512 extends WithHashTag[SHA512]("SHA-512")
