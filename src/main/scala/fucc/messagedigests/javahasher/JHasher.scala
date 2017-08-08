package fucc.messagedigests.javahasher

import java.security.MessageDigest

import fucc.common.JCryptoTag
import fucc.messagedigests.core._

class JHasher[T: JCryptoTag](
    algebra: JHashAlgebra[T])(implicit pureHasher: JPureHasher[T])
    extends HashingPrograms[MessageDigest,T](algebra)

object JHasher {
  def apply[T : JCryptoTag](implicit p: JPureHasher[T]) =
    new JHasher[T](new JHashAlgebra[T])
}
