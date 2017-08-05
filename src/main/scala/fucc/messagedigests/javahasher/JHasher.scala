package fucc.messagedigests.javahasher

import java.security.MessageDigest
import fucc.messagedigests.core._

class JHasher[T: HashTag](
    algebra: JHashAlgebra[T])(implicit pureHasher: JPureHasher[T])
    extends HashingPrograms[MessageDigest,T](algebra)

object JHasher {
  def apply[T : HashTag](implicit p: JPureHasher[T]) =
    new JHasher[T](new JHashAlgebra[T])
}
