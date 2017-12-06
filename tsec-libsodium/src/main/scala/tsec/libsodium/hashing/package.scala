package tsec.libsodium

import cats.effect.Sync
import cats.evidence.Is
import tsec.common._
import tsec.libsodium.ScalaSodium.{NullPtrBytes, NullPtrInt}
import tsec.libsodium.hashing.HashState$$

package object hashing {
  private[tsec] val HashState$$ : HKByteArrayNewt = new HKByteArrayNewt {
    type Repr[A] = Array[Byte]

    def is[G] = Is.refl[Array[Byte]]
  }

  type HashState[A] = HashState$$.Repr[A]

  object HashState {
    def apply[A](bytes: Array[Byte]): HashState[A]   = is[A].coerce(bytes)
    @inline def is[A]: Is[Array[Byte], HashState[A]] = HashState$$.is[A]
  }

  private[tsec] val Hash$$ : HKByteArrayNewt = new HKByteArrayNewt {
    type Repr[A] = Array[Byte]

    def is[G] = Is.refl[Array[Byte]]
  }

  type Hash[A] = Hash$$.Repr[A]

  object Hash {
    def apply[A](bytes: Array[Byte]): Hash[A]   = is[A].coerce(bytes)
    @inline def is[A]: Is[Array[Byte], Hash[A]] = Hash$$.is[A]
  }

  private[tsec] val BlakeKey$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[I]
  }

  type BlakeKey = BlakeKey$$.I

  object BlakeKey {
    def apply(bytes: Array[Byte]): BlakeKey   = is.flip.coerce(bytes)
    @inline def is: Is[BlakeKey, Array[Byte]] = BlakeKey$$.is
  }
}
