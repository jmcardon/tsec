package tsec.libsodium

import cats.evidence.Is
import tsec.common.TaggedByteArray

package object cipher {

  private[tsec] val Plaintext$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[I]
  }

  type PlainText = Plaintext$$.I

  object PlainText {
    def apply[A](bytes: Array[Byte]): PlainText = is.flip.coerce(bytes)
    @inline def is: Is[PlainText, Array[Byte]] = Plaintext$$.is
  }



  private[tsec] val SodiumKey$$ : LiftedByteArray = new LiftedByteArray {
    type AuthRepr[A] = Array[Byte]

    def is[G] = Is.refl[Array[Byte]]
  }

  /** Our newtype over private keys **/
  type SodiumKey[A] = SodiumKey$$.AuthRepr[A]

  private[tsec] val AuthTag$$ : LiftedByteArray = new LiftedByteArray {
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

  private[tsec] val StreamHeader$$: TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[I]
  }

  type CryptoStreamHeader = StreamHeader$$.I

  object CryptoStreamHeader {
    def apply[A](bytes: Array[Byte]): CryptoStreamHeader = is.flip.coerce(bytes)
    @inline def is: Is[CryptoStreamHeader, Array[Byte]] = StreamHeader$$.is
  }

  private[tsec] val StreamState$$: TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[I]
  }

  type CryptoStreamState = StreamState$$.I

  object CryptoStreamState {
    def apply[A](bytes: Array[Byte]): CryptoStreamState = is.flip.coerce(bytes)
    @inline def is: Is[CryptoStreamState, Array[Byte]] = StreamState$$.is
  }

  case class CryptoStreamST(state: CryptoStreamState, header: CryptoStreamHeader)

}
