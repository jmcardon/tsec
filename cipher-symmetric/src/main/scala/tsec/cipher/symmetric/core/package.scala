package tsec.cipher.symmetric

import cats.evidence.Is
import tsec.common.HK2ByteNewt

package object core {

  private[tsec] val Iv$$ : HK2ByteNewt = new HK2ByteNewt {
    type Repr[A, B] = Array[Byte]
    def is[A, B] = Is.refl[Array[Byte]]
  }

  type Iv[A, B] = Iv$$.Repr[A, B]

  object Iv {
    def apply[A, B](bytes: Array[Byte]): Iv[A, B]   = is[A, B].coerce(bytes)
    @inline def is[A, B]: Is[Array[Byte], Iv[A, B]] = Iv$$.is[A, B]
  }

}
