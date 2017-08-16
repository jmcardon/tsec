package tsec.messagedigests.instances

import java.security.MessageDigest
import tsec.core.CryptoTag
import tsec.messagedigests.core._

class JHasher[T: CryptoTag](algebra: JHashAlgebra[T])(implicit pureHasher: JPureHasher[T])
    extends HashingPrograms[MessageDigest, T](algebra)

object JHasher {

  def apply[T: CryptoTag](implicit p: JPureHasher[T]) =
    new JHasher[T](new JHashAlgebra[T])
}
