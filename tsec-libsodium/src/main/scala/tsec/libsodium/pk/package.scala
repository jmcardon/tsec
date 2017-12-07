package tsec.libsodium

import cats.evidence.Is
import tsec.common.HKByteArrayNewt

package object pk {

  // Todo: Macro??? Seriously this is so repetitive
  private[tsec] val PrivateEncKey$$ : HKByteArrayNewt = new HKByteArrayNewt {
    type Repr[A] = Array[Byte]

    def is[G] = Is.refl[Repr[G]]
  }

  type PrivateKey[A] = PrivateEncKey$$.Repr[A]

  //Todo: Check keyLen for building.
  object PrivateKey {
    def apply[A](bytes: Array[Byte]): PrivateKey[A]   = is[A].coerce(bytes)
    @inline def is[A]: Is[Array[Byte], PrivateKey[A]] = PrivateEncKey$$.is[A]
  }

  private[tsec] val PublicEncKey$$ : HKByteArrayNewt = new HKByteArrayNewt {
    type Repr[A] = Array[Byte]

    def is[G] = Is.refl[Repr[G]]
  }

  type PublicKey[A] = PublicEncKey$$.Repr[A]

  object PublicKey {
    def apply[A](bytes: Array[Byte]): PublicKey[A]   = is[A].coerce(bytes)
    @inline def is[A]: Is[Array[Byte], PublicKey[A]] = PublicEncKey$$.is[A]
  }

  final case class SodiumKeyPair[A](pubKey: PublicKey[A], privKey: PrivateKey[A])

}
