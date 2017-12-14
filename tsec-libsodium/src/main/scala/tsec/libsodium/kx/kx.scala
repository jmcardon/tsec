package tsec.libsodium

import cats.evidence.Is
import tsec.common.HKByteArrayNewt

package object kx {

  private[tsec] val SodiumKey$$ : HKByteArrayNewt = new HKByteArrayNewt {
    type Repr[A] = Array[Byte]

    def is[G] = Is.refl[Array[Byte]]
  }

  type SodiumKey[A] = SodiumKey$$.Repr[A]

  object SodiumKey {
    def apply[A](bytes: Array[Byte]): SodiumKey[A]   = is[A].coerce(bytes)
    @inline def is[A]: Is[Array[Byte], SodiumKey[A]] = SodiumKey$$.is[A]
  }


  trait PublicKey
  trait SecretKey
  trait SharedKey

  case class SodiumKeyPair(publicKey: SodiumKey[PublicKey], secretKey: SodiumKey[SecretKey])

  case class SodiumSharedKeyPair(receive: SodiumKey[SharedKey], send: SodiumKey[SharedKey])


  case object KeySessionError extends Exception with Product with Serializable {
    def cause: String = "KeySession generation Error"
    override def fillInStackTrace(): Throwable = this
  }

  case class KeySeedingError(n: Int) extends Exception with Product with Serializable {
    def cause: String = s"Got $n seeding bytes, expected ${ScalaSodium.crypto_kx_SEEDBYTES}"
    override def fillInStackTrace(): Throwable = this
  }


}
