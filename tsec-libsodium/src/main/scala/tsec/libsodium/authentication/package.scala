package tsec.libsodium

import cats.evidence.Is

package object authentication {

  private[tsec] val MAC$$ : LiftedByteArray = new LiftedByteArray {
    type AuthRepr[A] = Array[Byte]

    def is[G] = Is.refl[AuthRepr[G]]
  }

  type SodiumMAC[A] = MAC$$.AuthRepr[A]

  //Todo: Type constraints
  object SodiumMAC {
    def apply[A](bytes: Array[Byte]): SodiumMAC[A]   = is[A].coerce(bytes)
    @inline def is[A]: Is[Array[Byte], SodiumMAC[A]] = MAC$$.is[A]
  }

  private[tsec] val SodiumMACKey$$ : LiftedByteArray = new LiftedByteArray {
    type AuthRepr[A] = Array[Byte]

    def is[G] = Is.refl[AuthRepr[G]]
  }

  type SodiumMACKey[A] = SodiumMACKey$$.AuthRepr[A]

  object SodiumMACKey {
    def apply[A](bytes: Array[Byte]): SodiumMACKey[A]   = is[A].coerce(bytes)
    @inline def is[A]: Is[Array[Byte], SodiumMACKey[A]] = SodiumMACKey$$.is[A]
  }

}
