package tsec.messagedigests.imports

import tsec.messagedigests.core._

class JHasher[T: DigestTag](
    algebra: JHashAlgebra[T]
) extends HashingPrograms[T](algebra)

object JHasher {

  def apply[T: DigestTag] = new JHasher[T](new JHashAlgebra[T])

  implicit def genHasher[T: DigestTag] = apply[T]
}
