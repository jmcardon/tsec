package tsec.mac

import cats.evidence.Is
import tsec.common.HKByteNewt
import tsec.mac.core.MacTag

package object core {

  private[tsec] val MAC$$ : HKByteNewt = new HKByteNewt {
    type Repr[A] = Array[Byte]
    def is[A] = Is.refl[Array[Byte]]
  }

  type MAC[A] = MAC$$.Repr[A]

  object MAC {
    def apply[A: MacTag](bytes: Array[Byte]): MAC[A] = is[A].coerce(bytes)
    @inline def is[A]: Is[Array[Byte], MAC[A]]       = MAC$$.is[A]
  }

}
