package fucc.all.encryption.messagedigests.javahasher

import fucc.all.encryption.messagedigests.core._

class JHasher[T: HashTag: PureHasher](
    algebra: JHashAlgebra[T])
    extends HashingPrograms[T](algebra)

object JHasher {
  def apply[T : HashTag: PureHasher] =
    new JHasher[T](new JHashAlgebra[T])

  lazy val MD5: JHasher[MD5] = apply[MD5]
  lazy val SHA1: JHasher[SHA1] = apply[SHA1]
  lazy val SHA256: JHasher[SHA256] = apply[SHA256]
  lazy val SHA512: JHasher[SHA512] = apply[SHA512]

}
