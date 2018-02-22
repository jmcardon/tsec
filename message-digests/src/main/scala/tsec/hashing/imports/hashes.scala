package tsec.hashing.imports

import cats.effect.Sync
import fs2.Pipe
import fs2.hash._

sealed trait MD5

object MD5 extends AsCryptoHash[MD5]("MD5") {
  def hashPipe[F[_]](implicit F: Sync[F], S: DummyImplicit): Pipe[F, Byte, Byte] = md5[F]
}

sealed trait SHA1

object SHA1 extends AsCryptoHash[SHA1]("SHA-1") {
  def hashPipe[F[_]](implicit F: Sync[F], S: DummyImplicit): Pipe[F, Byte, Byte] =
    sha1[F]
}

sealed trait SHA256

object SHA256 extends AsCryptoHash[SHA256]("SHA-256") {
  def hashPipe[F[_]](implicit F: Sync[F], S: DummyImplicit): Pipe[F, Byte, Byte] =
    sha256[F]
}

sealed trait SHA512

object SHA512 extends AsCryptoHash[SHA512]("SHA-512") {
  def hashPipe[F[_]](implicit F: Sync[F], S: DummyImplicit): Pipe[F, Byte, Byte] =
    sha512[F]
}
