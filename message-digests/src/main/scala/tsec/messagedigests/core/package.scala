package tsec.messagedigests

import cats.evidence.Is
import tsec.common._

package object core {
  private[tsec] val DigestHash$$ : HKByteNewt = new HKByteNewt {
    type Repr[A] = Array[Byte]

    def is[A] = Is.refl[Array[Byte]]
  }

  type CryptoHash[A] = DigestHash$$.Repr[A]

  object CryptoHash {
    @inline def apply[A: DigestTag](bytes: Array[Byte]): CryptoHash[A] = is[A].coerce(bytes)
    @inline def is[A: DigestTag]: Is[Array[Byte], CryptoHash[A]]       = DigestHash$$.is[A]
  }

}
