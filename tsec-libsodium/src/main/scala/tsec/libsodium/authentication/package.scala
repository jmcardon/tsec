package tsec.libsodium

import cats.evidence.Is
import tsec.common.HKByteArrayNewt
import tsec.libsodium.authentication.internal.SodiumMacAlg

package object authentication {

  private[tsec] val MAC$$ : HKByteArrayNewt = new HKByteArrayNewt {
    type Repr[A] = Array[Byte]

    def is[G] = Is.refl[Repr[G]]
  }

  type SodiumMAC[A] = MAC$$.Repr[A]

  object SodiumMAC {
    def apply[A: SodiumMacAlg](bytes: Array[Byte]): SodiumMAC[A]   = is[A].coerce(bytes)
    @inline def is[A: SodiumMacAlg]: Is[Array[Byte], SodiumMAC[A]] = MAC$$.is[A]
  }

  private[tsec] val SodiumMACKey$$ : HKByteArrayNewt = new HKByteArrayNewt {
    type Repr[A] = Array[Byte]

    def is[G] = Is.refl[Repr[G]]
  }

  type SodiumMACKey[A] = SodiumMACKey$$.Repr[A]

  object SodiumMACKey {
    def apply[A: SodiumMacAlg](bytes: Array[Byte]): SodiumMACKey[A]   = is[A].coerce(bytes)
    @inline def is[A: SodiumMacAlg]: Is[Array[Byte], SodiumMACKey[A]] = SodiumMACKey$$.is[A]
  }

}
