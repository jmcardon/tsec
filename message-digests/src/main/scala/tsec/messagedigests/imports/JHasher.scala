package tsec.messagedigests.imports

import tsec.common.ByteEV
import tsec.messagedigests.core._

class JHasher[T: DigestTag](
    algebra: JHashAlgebra[T]
)(implicit gen: ByteEV[T])
    extends HashingPrograms[T](algebra)

object JHasher {

  def apply[T: DigestTag](implicit gen: ByteEV[T]) =
    new JHasher[T](new JHashAlgebra[T])

  implicit def genHasher[T: DigestTag: ByteEV] = apply[T]
}
