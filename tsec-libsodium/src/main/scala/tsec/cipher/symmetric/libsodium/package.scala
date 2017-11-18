package tsec.cipher.symmetric

import cats.effect.Sync
import cats.evidence.Is
import tsec.{ScalaSodium => Sodium}
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.imports._
import tsec.cipher.symmetric.libsodium.internal.{SodiumCipherAlgebra, SodiumKeyGenerator}
import cats.syntax.all._
import tsec.cipher.symmetric.libsodium.AADLS$$
import tsec.common._

package object libsodium {

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
