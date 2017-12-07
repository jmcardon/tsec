package tsec.libsodium.pk

import cats.evidence.Is
import tsec.common._

package object encryption {

  private[tsec] val PKAuthTag$$ : HKByteArrayNewt = new HKByteArrayNewt {
    type Repr[A] = Array[Byte]

    def is[G] = Is.refl[Repr[G]]
  }

  type PKAuthTag[A] = PKAuthTag$$.Repr[A]

  object PKAuthTag {
    def apply[A](bytes: Array[Byte]): PKAuthTag[A]   = is[A].coerce(bytes)
    @inline def is[A]: Is[Array[Byte], PKAuthTag[A]] = PKAuthTag$$.is[A]
  }

  private[tsec] val SharedKey$$ : HKByteArrayNewt = new HKByteArrayNewt {
    type Repr[A] = Array[Byte]

    def is[G] = Is.refl[Repr[G]]
  }

  type SharedKey[A] = SharedKey$$.Repr[A]

  object SharedKey {
    def apply[A](bytes: Array[Byte]): SharedKey[A]   = is[A].coerce(bytes)
    @inline def is[A]: Is[Array[Byte], SharedKey[A]] = SharedKey$$.is[A]
  }
}
