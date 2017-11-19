package tsec.libsodium.cipher.internal

import cats.effect.Sync
import tsec.ScalaSodium
import tsec.cipher.symmetric.PlainText
import tsec.libsodium.cipher._

trait SodiumCipherAlgebra[A, K[_]] {

  /** Encrypt our plaintext with a typed secret key,
    * and append the authentication tag to the ciphertext
    *
    * @param plainText the plaintext to encrypt
    * @param key the SecretKey to use
    * @return
    */
  def encrypt[F[_]](plainText: PlainText, key: K[A])(implicit F: Sync[F], S: ScalaSodium): F[SodiumCipherText[A]]

  /** Decrypt our ciphertext, that has the authentication tag in a joined
    * manner.
    *
    * @param cipherText the plaintext to encrypt
    * @param key the SecretKey to use
    * @return
    */
  def decrypt[F[_]](cipherText: SodiumCipherText[A], key: K[A])(implicit F: Sync[F], S: ScalaSodium): F[PlainText]

  /** Encrypt our plaintext with a typed secret key,
    * and return the authentication tag separately
    *
    * @param plainText the plaintext to encrypt
    * @param key the SecretKey to use
    * @return
    */
  def encryptDetached[F[_]](plainText: PlainText, key: K[A])(
      implicit F: Sync[F],
      S: ScalaSodium
  ): F[(SodiumCipherText[A], AuthTag[A])]

  /** Decrypt our ciphertext, with the authentication tag
    * fed in separately.
    *
    * @param cipherText the plaintext to encrypt
    * @param key the SecretKey to use
    * @return
    */
  def decryptDetached[F[_]](cipherText: SodiumCipherText[A], key: K[A], authTag: AuthTag[A])(
      implicit F: Sync[F],
      S: ScalaSodium
  ): F[PlainText]

}
