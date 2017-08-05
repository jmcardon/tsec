package fucc.all.encryption.messagedigests.javahasher

import java.security.MessageDigest
import fucc.all.encryption.messagedigests.core._
import fucc.all.encryption.messagedigests.javahasher.implicits._

class JHasher[T: HashTag](
    algebra: JHashAlgebra[T])(implicit pureHasher: PureHasher[MessageDigest, T])
    extends HashingPrograms[MessageDigest,T](algebra)

object JHasher {
  def apply[T : HashTag](implicit p: PureHasher[MessageDigest, T]) =
    new JHasher[T](new JHashAlgebra[T])

  lazy val MD5: JHasher[MD5] = apply[MD5]
  lazy val SHA1: JHasher[SHA1] = apply[SHA1]
  lazy val SHA256: JHasher[SHA256] = apply[SHA256]
  lazy val SHA512: JHasher[SHA512] = apply[SHA512]

}
