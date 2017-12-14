package tsec.libsodium

import tsec.libsodium.cipher.SodiumKey

package object kx {

  final case class SodiumSharedKeyPair[A](receive: SodiumKey[A], send: SodiumKey[A])

  case object KeySessionError extends Exception with Product with Serializable {
    def cause: String = "KeySession generation Error"
    override def fillInStackTrace(): Throwable = this
  }

  case class KeySeedingError(n: Int) extends Exception with Product with Serializable {
    def cause: String = s"Got $n seeding bytes, expected ${ScalaSodium.crypto_kx_SEEDBYTES}"
    override def fillInStackTrace(): Throwable = this
  }


}
