package tsec.libsodium

import cats.evidence.Is
import tsec.common.TaggedByteArray

package object cipher {

  /** Parametrically polymorphic existential over crypto keys
    *
    */
  sealed trait LiftedKey {
    type AuthRepr[A] <: Array[Byte]
    def is[G]: Is[Array[Byte], AuthRepr[G]]
  }

  private[tsec] val SodiumKey$$ : LiftedKey = new LiftedKey {
    type AuthRepr[A] = Array[Byte]

    def is[G] = Is.refl[Array[Byte]]
  }

  /** Our newtype over private keys **/
  type SodiumKey[A] = SodiumKey$$.AuthRepr[A]

  private[tsec] val AuthTag$$ : LiftedKey = new LiftedKey {
    type AuthRepr[A] = Array[Byte]

    def is[G] = Is.refl[Array[Byte]]
  }

  /** Our newtype over authentication tags **/
  type AuthTag[A] = AuthTag$$.AuthRepr[A]

  object AuthTag {
    def apply[A](bytes: Array[Byte]): AuthTag[A]   = AuthTag$$.is[A].coerce(bytes)
    @inline def is[A]: Is[Array[Byte], AuthTag[A]] = AuthTag$$.is[A]
  }

  object SodiumKey {
    def apply[A](bytes: Array[Byte]): SodiumKey[A]   = is[A].coerce(bytes)
    @inline def is[A]: Is[Array[Byte], SodiumKey[A]] = SodiumKey$$.is[A]
  }

  private[tsec] val AADLS$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[I]
  }

  type SodiumAAD = AADLS$$.I

  object SodiumAAD {
    def apply[A](bytes: Array[Byte]): SodiumAAD = is.flip.coerce(bytes)
    @inline def is: Is[SodiumAAD, Array[Byte]]  = AADLS$$.is
  }

}
