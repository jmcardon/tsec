package tsec.cipher.symmetric.libsodium.internal

import cats.effect.Sync
import tsec.ScalaSodium
import tsec.cipher.symmetric.PlainText
import tsec.cipher.symmetric.libsodium.SodiumCipherText

trait SodiumCipherAlgebra[A, K[_]] {

  /** Encrypt our plaintext with a tagged secret key
    *
    * @param plainText the plaintext to encrypt
    * @param key the SecretKey to use
    * @return
    */
  def encrypt[F[_]](plainText: PlainText, key: K[A])(implicit F: Sync[F], S: ScalaSodium): F[SodiumCipherText[A]]

  /** Decrypt our ciphertext
    *
    * @param cipherText the plaintext to encrypt
    * @param key the SecretKey to use
    * @return
    */
  def decrypt[F[_]](cipherText: SodiumCipherText[A], key: K[A])(implicit F: Sync[F], S: ScalaSodium): F[PlainText]

}
