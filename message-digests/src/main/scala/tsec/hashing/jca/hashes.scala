package tsec.hashing.jca

import cats.effect.Sync
import fs2.Pipe
import fs2.hash._

sealed trait MD5

object MD5 extends AsCryptoHash[MD5]("MD5")

sealed trait SHA1

object SHA1 extends AsCryptoHash[SHA1]("SHA-1")

sealed trait SHA256

object SHA256 extends AsCryptoHash[SHA256]("SHA-256")

sealed trait SHA512

object SHA512 extends AsCryptoHash[SHA512]("SHA-512")
