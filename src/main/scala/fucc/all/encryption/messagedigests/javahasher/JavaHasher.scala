package fucc.all.encryption.messagedigests.javahasher

import cats.effect.IO
import fucc.all.encryption.messagedigests.core._
import org.apache.commons.codec.binary.Base64

class JavaHasher[T <: HashAlgorithm: HashTag: PureHasher](
    algebra: JavaDigestAlgebra[T])
    extends HashingPrograms[IO, T](algebra)

object JavaHasher {
  def apply[T <: HashAlgorithm: HashTag: PureHasher] =
    new JavaHasher[T](new JavaDigestAlgebra[T])

  lazy val MD5: JavaHasher[MD5] = apply[MD5]
  lazy val SHA1: JavaHasher[SHA1] = apply[SHA1]
  lazy val SHA256: JavaHasher[SHA256] = apply[SHA256]
  lazy val SHA512: JavaHasher[SHA512] = apply[SHA512]

  implicit class HasherOps[T <: HashAlgorithm, C <: JavaHasher[T]](
      val hasher: C)
      extends AnyVal {
    def hashStringToBase64(s: String): IO[String] =
      hasher
        .hash[String](s)(defaultStringEncoder)
        .map(b => Base64.encodeBase64String(hasher.p.bytes(b)))
  }
}
