package tsec.libsodium.pk

import cats.evidence.Is
import tsec.common.HKByteArrayNewt

package object signatures {

  private[tsec] val RawMessage$$ : HKByteArrayNewt = new HKByteArrayNewt {
    type Repr[A] = Array[Byte]

    def is[G] = Is.refl[Repr[G]]
  }

  type RawMessage[A] = RawMessage$$.Repr[A]

  object RawMessage {
    def apply[A](bytes: Array[Byte]): RawMessage[A]   = is[A].coerce(bytes)
    @inline def is[A]: Is[Array[Byte], RawMessage[A]] = RawMessage$$.is[A]
  }

  private[tsec] val SignedMessage$$ : HKByteArrayNewt = new HKByteArrayNewt {
    type Repr[A] = Array[Byte]

    def is[G] = Is.refl[Repr[G]]
  }

  type SignedMessage[A] = SignedMessage$$.Repr[A]

  object SignedMessage {
    def apply[A](bytes: Array[Byte]): SignedMessage[A]   = is[A].coerce(bytes)
    @inline def is[A]: Is[Array[Byte], SignedMessage[A]] = SignedMessage$$.is[A]
  }


  private[tsec] val Signature$$ : HKByteArrayNewt = new HKByteArrayNewt {
    type Repr[A] = Array[Byte]

    def is[G] = Is.refl[Repr[G]]
  }

  type Signature[A] = Signature$$.Repr[A]

  object Signature {
    def apply[A](bytes: Array[Byte]): Signature[A]   = is[A].coerce(bytes)
    @inline def is[A]: Is[Array[Byte], Signature[A]] = Signature$$.is[A]
  }

}
