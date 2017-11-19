package tsec.libsodium.cipher.internal

import cats.effect.Sync
import tsec.ScalaSodium
import tsec.cipher.symmetric._
import tsec.libsodium.cipher._

trait SodiumAEADAlgebra[A, K[_]] {

  /** Encrypt our plaintext with a typed secret key,
    * and append the authentication tag to the ciphertext,
    * using additional authentication data
    *
    */
  def encryptAAD[F[_]](plaintext: PlainText, key: K[A], aad: SodiumAAD)(
      implicit F: Sync[F],
      S: ScalaSodium
  ): F[SodiumCipherText[A]]

  /** Decrypt our ciphertext, that has the authentication tag in a joined
    * manner.
    */
  def decryptAAD[F[_]](cipherText: SodiumCipherText[A], key: K[A], aad: SodiumAAD)(
      implicit F: Sync[F],
      S: ScalaSodium
  ): F[PlainText]

  /** Encrypt our plaintext with a typed secret key,
    * and return the authentication tag separately
    *
    */
  def encryptAADDetached[F[_]](plainText: PlainText, key: K[A], aad: SodiumAAD)(
      implicit F: Sync[F],
      S: ScalaSodium
  ): F[(SodiumCipherText[A], AuthTag[A])]

  /** Decrypt our ciphertext, with the authentication tag
    * fed in separately.
    *
    */
  def decryptAADDetached[F[_]](cipherText: SodiumCipherText[A], key: K[A], authTag: AuthTag[A], aad: SodiumAAD)(
      implicit F: Sync[F],
      S: ScalaSodium
  ): F[PlainText]

}
