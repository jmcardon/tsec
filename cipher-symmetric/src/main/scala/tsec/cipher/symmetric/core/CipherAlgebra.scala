package tsec.cipher.symmetric.core

import tsec.cipher.symmetric.{AAD, AuthTag, CipherText, PlainText}

trait CipherAlgebra[F[_], A, M, P, K[_]] {

  /** Encrypt our plaintext with a tagged secret key
    *
    * @param plainText the plaintext to encrypt
    * @param key       the SecretKey to use
    * @return
    */
  def encrypt(plainText: PlainText, key: K[A], iv: Iv[A, M]): F[CipherText[A, M, P]]

  /** Decrypt our ciphertext
    *
    * @param cipherText the plaintext to encrypt
    * @param key        the SecretKey to use
    * @return
    */
  def decrypt(cipherText: CipherText[A, M, P], key: K[A]): F[PlainText]

}

//Todo: Abstract over auth tag, combined and non-combined
trait AEADAlgebra[F[_], A, M, P, K[_]] extends CipherAlgebra[F, A, M, P, K] {

  /** Encrypt our plaintext with a tagged secret key
    *
    * @param plainText the plaintext to encrypt
    * @param key       the SecretKey to use
    * @return
    */
  def encryptDetached(plainText: PlainText, key: K[A], iv: Iv[A, M]): F[(CipherText[A, M, P], AuthTag[A])]

  /** Decrypt our ciphertext
    *
    * @param cipherText the plaintext to encrypt
    * @param key        the SecretKey to use
    * @return
    */
  def decryptDetached(cipherText: CipherText[A, M, P], key: K[A], tag: AuthTag[A]): F[PlainText]

  /** Encrypt our plaintext using additional authentication parameters,
    * Primarily for GCM mode and CCM mode
    * Other modes will return a cipherError attempting this
    *
    * @param plainText the plaintext to encrypt
    * @param key       the SecretKey to use
    * @param aad       The additional authentication information
    * @return
    */
  def encryptAAD(plainText: PlainText, key: K[A], iv: Iv[A, M], aad: AAD): F[CipherText[A, M, P]]

  /** Decrypt our ciphertext using additional authentication parameters,
    * Primarily for GCM mode and CCM mode
    * Other modes will return a cipherError attempting this
    *
    * @param cipherText the plaintext to encrypt
    * @param key        the SecretKey to use
    * @param aad        The additional authentication information
    * @return
    */
  def decryptAAD(cipherText: CipherText[A, M, P], key: K[A], aad: AAD): F[PlainText]

  /** Encrypt our plaintext using additional authentication parameters,
    * Primarily for GCM mode and CCM mode
    * Other modes will return a cipherError attempting this
    *
    * @param plainText the plaintext to encrypt
    * @param key       the SecretKey to use
    * @param aad       The additional authentication information
    * @return
    */
  def encryptAADDetached(plainText: PlainText, key: K[A], iv: Iv[A, M], aad: AAD): F[(CipherText[A, M, P], AuthTag[A])]

  /** Decrypt our ciphertext using additional authentication parameters,
    * Primarily for GCM mode and CCM mode
    * Other modes will return a cipherError attempting this
    *
    * @param cipherText the plaintext to encrypt
    * @param key        the SecretKey to use
    * @param aad        The additional authentication information
    * @return
    */
  def decryptAADDetached(cipherText: CipherText[A, M, P], key: K[A], aad: AAD, tag: AuthTag[A]): F[PlainText]

}
