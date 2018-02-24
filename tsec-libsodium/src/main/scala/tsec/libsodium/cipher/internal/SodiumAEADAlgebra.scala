package tsec.libsodium.cipher.internal

import tsec.cipher.symmetric.core._
import cats.effect.Sync
import tsec.libsodium.ScalaSodium

trait SodiumAEADAlgebra[A, K[_]] {

  /** Encrypt our plaintext with a typed secret key,
    * and append the authentication tag to the ciphertext,
    * using additional authentication data
    *
    */
  def encrypt[F[_]](plaintext: PlainText, key: K[A])(
      implicit F: Sync[F],
      S: ScalaSodium
  ): F[CipherText[A]]

  /** Decrypt our ciphertext, that has the authentication tag in a joined
    * manner.
    */
  def decrypt[F[_]](cipherText: CipherText[A], key: K[A])(
    implicit F: Sync[F],
    S: ScalaSodium
  ): F[PlainText]

  /** Encrypt our plaintext with a typed secret key,
    * and append the authentication tag to the ciphertext,
    * using additional authentication data
    *
    */
  def encryptAAD[F[_]](plaintext: PlainText, key: K[A], aad: AAD)(
      implicit F: Sync[F],
      S: ScalaSodium
  ): F[CipherText[A]]

  /** Decrypt our ciphertext, that has the authentication tag in a joined
    * manner.
    */
  def decryptAAD[F[_]](cipherText: CipherText[A], key: K[A], aad: AAD)(
      implicit F: Sync[F],
      S: ScalaSodium
  ): F[PlainText]

  /** Encrypt our plaintext with a typed secret key,
    * and return the authentication tag separately
    *
    */
  def encryptAADDetached[F[_]](plainText: PlainText, key: K[A], aad: AAD)(
      implicit F: Sync[F],
      S: ScalaSodium
  ): F[(CipherText[A], AuthTag[A])]

  /** Decrypt our ciphertext, with the authentication tag
    * fed in separately.
    *
    */
  def decryptAADDetached[F[_]](cipherText: CipherText[A], key: K[A], authTag: AuthTag[A], aad: AAD)(
      implicit F: Sync[F],
      S: ScalaSodium
  ): F[PlainText]

}
