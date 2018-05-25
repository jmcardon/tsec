package tsec.kx

import tsec.cipher.symmetric.libsodium.SodiumKey
import tsec.common.ArrayHKNewt
import tsec.libsodium.ScalaSodium

package object libsodium {

  type PrivateKey[A] = PrivateKey.Type[A]

  //Todo: Check keyLen for building.
  object PrivateKey extends ArrayHKNewt

  type PublicKey[A] = PublicKey.Type[A]

  object PublicKey extends ArrayHKNewt

  final case class SodiumKeyPair[A](pubKey: PublicKey[A], privKey: PrivateKey[A])

  final case class SodiumSharedKeyPair[A](receive: SodiumKey[A], send: SodiumKey[A])

  case object KeySessionError extends Exception with Product with Serializable {
    def cause: String                          = "KeySession generation Error"
    override def fillInStackTrace(): Throwable = this
  }

  case class KeySeedingError(n: Int) extends Exception with Product with Serializable {
    def cause: String                          = s"Got $n seeding bytes, expected ${ScalaSodium.crypto_kx_SEEDBYTES}"
    override def fillInStackTrace(): Throwable = this
  }

}
