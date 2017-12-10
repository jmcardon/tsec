package tsec.signature

import cats.evidence.Is
import tsec.common._

package object core {

  private[tsec] val Signature$$ : HKByteNewt = new HKByteNewt {
    type Repr[A] = Array[Byte]

    def is[A] = Is.refl[Array[Byte]]
  }

  type CryptoSignature[A] = Signature$$.Repr[A]

  object CryptoSignature {
    def apply[A: SigAlgoTag](bytes: Array[Byte]): CryptoSignature[A]   = is[A].coerce(bytes)
    @inline def is[A: SigAlgoTag]: Is[Array[Byte], CryptoSignature[A]] = Signature$$.is[A]
  }

}
