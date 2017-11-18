package tsec.cipher.symmetric

import cats.effect.Sync
import cats.evidence.Is
import tsec.{ScalaSodium => Sodium}
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.imports._
import tsec.cipher.symmetric.libsodium.internal.{SodiumCipherAlgebra, SodiumKeyGenerator}
import cats.syntax.all._
import tsec.cipher.symmetric.libsodium.AuthTag$$
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

  type AuthTag[A] = AuthTag$$.AuthRepr[A]

  object AuthTag {
    def apply[A: SodiumAuthCipher](bytes: Array[Byte]): AuthTag[A] = AuthTag$$.is[A].coerce(bytes)
    @inline def is[A]: Is[Array[Byte], AuthTag[A]]                 = AuthTag$$.is[A]
  }

  object SodiumKey {
    def apply[A: SodiumAuthCipher](bytes: Array[Byte]): SodiumKey[A] = is[A].coerce(bytes)
    @inline def is[A]: Is[Array[Byte], SodiumKey[A]]                 = SodiumKey$$.is[A]
  }

  trait SodiumAuthCipher[A] extends SymmetricCipher[A] {
    val nonceLen: Int
    val macLen: Int

    /** Encrypt the plaintext using the nonce (in other words initialization vector)
      * in an api-compatible way with libsodium
      *
      * Mutates the cout array, same as libsodium
      *
      * @param cout ciphertext
      * @param pt plaintext
      * @param nonce Initializaiton vector
      * @param key the encryption key
      * @return 0 if successful, any other number means unsuccessful
      */
    private[tsec] def sodiumEncrypt(cout: Array[Byte], pt: PlainText, nonce: Array[Byte], key: SodiumKey[A])(
        implicit S: Sodium
    ): Int

    /** Decrypt the ciphertext, in an api-compat way with libsodium authenticated encryption
      *
      * @param origOut the original message
      * @param ct the ciphertext
      * @param key the key
      * @return 0 if successful, any other number indicates unsuccessful
      */
    private[tsec] def sodiumDecrypt(origOut: Array[Byte], ct: SodiumCipherText[A], key: SodiumKey[A])(
        implicit S: Sodium
    ): Int

    /** Encrypt the plaintext using the nonce (in other words initialization vector)
      * in an api-compatible way with libsodium
      *
      * Mutates the cout array, same as libsodium
      *
      * @param cout ciphertext
      * @param pt plaintext
      * @param nonce Initializaiton vector
      * @param key the encryption key
      * @return 0 if successful, any other number means unsuccessful
      */
    private[tsec] def sodiumEncryptDetached(
        cout: Array[Byte],
        tagOut: Array[Byte],
        pt: PlainText,
        nonce: Array[Byte],
        key: SodiumKey[A]
    )(implicit S: Sodium): Int

    /** Decrypt the ciphertext, in an api-compat way with libsodium authenticated encryption
      *
      * @param origOut the original message
      * @param ct the ciphertext
      * @param key the key
      * @return 0 if successful, any other number indicates unsuccessful
      */
    private[tsec] def sodiumDecryptDetached(
        origOut: Array[Byte],
        ct: SodiumCipherText[A],
        tagIn: AuthTag[A],
        key: SodiumKey[A]
    )(implicit S: Sodium): Int

  }

  trait SodiumAEADCipher[A] extends SymmetricCipher[A]

}
