package tsec.cipher.symmetric

import cats.effect.Sync
import cats.evidence.Is
import tsec.ScalaSodium
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.imports._
import tsec.cipher.symmetric.libsodium.internal.{SodiumCipherAlgebra, SodiumKeyGenerator}
import cats.syntax.all._
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

  type SodiumKey[A] = SodiumKey$$.AuthRepr[A]

  object SodiumKey {
    def apply[A: SodiumAuthCipher](bytes: Array[Byte]): SodiumKey[A] = is[A].coerce(bytes)
    @inline def is[A]: Is[Array[Byte], SodiumKey[A]]                 = SodiumKey$$.is[A]
  }

  trait SodiumAuthCipher[A] extends SymmetricCipher[A] {
    val nonceLen: Int
    val macLen: Int
  }
  trait SodiumAEADCipher[A] extends SymmetricCipher[A]

  abstract class SodiumCipherPlatform[A]
      extends SodiumKeyGenerator[A, SodiumKey]
      with SodiumAuthCipher[A]
      with SodiumCipherAlgebra[A, SodiumKey] {
    implicit val authCiper: SodiumAuthCipher[A] = this
  }

  sealed trait XSalsa20Poly1305

  object XSalsa20Poly1305 extends SodiumCipherPlatform[XSalsa20Poly1305] {

    def algorithm: String = "XSalsa20Poly1305"

    val nonceLen: Int = ScalaSodium.crypto_secretbox_xsalsa20poly1305_NONCEBYTES

    val keyLength: Int = ScalaSodium.crypto_secretbox_xsalsa20poly1305_KEYBYTES

    val macLen: Int = ScalaSodium.crypto_secretbox_xsalsa20poly1305_MACBYTES

    def generateKey[F[_]](implicit F: Sync[F], s: ScalaSodium): F[SodiumKey[XSalsa20Poly1305]] =
      F.delay(generateKeyUnsafe)

    def generateKeyUnsafe(implicit s: ScalaSodium): SodiumKey[XSalsa20Poly1305] = {
      val bytes = new Array[Byte](keyLength)
      s.crypto_secretbox_keygen(bytes)
      SodiumKey[XSalsa20Poly1305](bytes)
    }

    def buildKey[F[_]](key: Array[Byte])(implicit F: Sync[F], s: ScalaSodium): F[SodiumKey[XSalsa20Poly1305]] =
      if (key.length != keyLength)
        F.raiseError(CipherKeyBuildError("Invalid Key length f"))
      else
        F.pure(SodiumKey[XSalsa20Poly1305](key))

    def buildKeyUnsafe(key: Array[Byte])(implicit s: ScalaSodium): SodiumKey[XSalsa20Poly1305] =
      SodiumKey[XSalsa20Poly1305](key)

    def encrypt[F[_]](plainText: PlainText, key: SodiumKey[XSalsa20Poly1305])(
        implicit F: Sync[F],
        S: ScalaSodium
    ): F[SodiumCipherText[XSalsa20Poly1305]] = F.delay {
      val outArray = new Array[Byte](plainText.content.length + macLen)
      val nonce    = new Array[Byte](nonceLen)
      S.randombytes_buf(nonce, nonceLen)
      val r = S.crypto_secretbox_easy(outArray, plainText.content, plainText.content.length, nonce, key)
      if (r != 0)
        throw EncryptError("Invalid encryption Info")

      SodiumCipherText[XSalsa20Poly1305](outArray, nonce)
    }

    def decrypt[F[_]](cipherText: SodiumCipherText[XSalsa20Poly1305], key: SodiumKey[XSalsa20Poly1305])(
        implicit F: Sync[F],
        S: ScalaSodium
    ): F[PlainText] = F.delay {
      val originalMessage = new Array[Byte](cipherText.content.length - macLen)
      val r =
        S.crypto_secretbox_open_easy(originalMessage, cipherText.content, cipherText.content.length, cipherText.iv, key)
      if (r != 0)
        throw DecryptError("Invalid Decryption info")

      PlainText(originalMessage)
    }
  }

}
