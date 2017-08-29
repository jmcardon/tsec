package tsec.cipher.symmetric.core

import tsec.cipher.common._
import tsec.cipher.symmetric.instances.SecretKey

trait SymmetricCipherAlgebra[F[_], A, M, P, K[_]] {
  type C

  def genInstance: F[C]

  /*
  Stateful operations for internal use
  We can choose to defer them or catch the effect somehow
   */
  protected[symmetric] def initEncryptor(e: C, secretKey: K[A]): F[Unit]

  protected[symmetric] def initDecryptor(
      decryptor: C,
      key: K[A],
      iv: Array[Byte]
  ): F[Unit]

  protected[symmetric] def setAAD(e: C, aad: AAD): F[Unit]
  /*
  End stateful ops
   */

  /**
    * Encrypt our plaintext with a tagged secret key
    *
    * @param plainText the plaintext to encrypt
    * @param key the SecretKey to use
    * @return
    */
  def encrypt(plainText: PlainText[A, M, P], key: K[A]): F[CipherText[A, M, P]]

  /**
    * Encrypt our plaintext using additional authentication parameters,
    * Primarily for GCM mode and CCM mode
    * Other modes will return a cipherError attempting this
    *
    * @param plainText the plaintext to encrypt
    * @param key the SecretKey to use
    * @param aad The additional authentication information
    * @return
    */
  def encryptAAD(plainText: PlainText[A, M, P], key: K[A], aad: AAD): F[CipherText[A, M, P]]

  /**
    * Decrypt our ciphertext
    *
    * @param cipherText the plaintext to encrypt
    * @param key the SecretKey to use
    * @return
    */
  def decrypt(cipherText: CipherText[A, M, P], key: K[A]): F[PlainText[A, M, P]]

  /**
    * Decrypt our ciphertext using additional authentication parameters,
    * Primarily for GCM mode and CCM mode
    * Other modes will return a cipherError attempting this
    *
    * @param cipherText the plaintext to encrypt
    * @param key the SecretKey to use
    * @param aad The additional authentication information
    * @return
    */
  def decryptAAD(cipherText: CipherText[A, M, P], key: K[A], aad: AAD): F[PlainText[A, M, P]]

}
