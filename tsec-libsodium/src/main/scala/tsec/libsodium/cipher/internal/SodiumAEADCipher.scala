package tsec.libsodium.cipher.internal

import tsec.cipher.symmetric._
import tsec.libsodium.ScalaSodium
import tsec.libsodium.cipher._

//Todo: Extend SodiumAuthCipher
trait SodiumAEADCipher[A] {
  def algorithm: String

  val nonceLen: Int
  val authTagLen: Int

  /** Encrypt the plaintext using the nonce (in other words initialization vector)
    * in an api-compatible way with libsodium
    *
    * Mutates the cout array, same as libsodium
    *
    * @param cout ciphertext
    * @param pt plaintext
    * @param nonce Initialization vector
    * @param key the encryption key
    * @return 0 if successful, any other number means unsuccessful
    */
  private[tsec] def sodiumEncrypt(cout: Array[Byte], pt: PlainText, nonce: Array[Byte], key: SodiumKey[A])(
      implicit S: ScalaSodium
  ): Int

  /** Encrypt the plaintext using the nonce (in other words initialization vector)
    * in an api-compatible way with libsodium
    *
    * Mutates the cout array, same as libsodium
    *
    * @param cout ciphertext
    * @param pt plaintext
    * @param nonce Initialization vector
    * @param key the encryption key
    * @return 0 if successful, any other number means unsuccessful
    */
  private[tsec] def sodiumEncryptDetached(
      cout: Array[Byte],
      tagOut: Array[Byte],
      pt: PlainText,
      nonce: Array[Byte],
      key: SodiumKey[A]
  )(implicit S: ScalaSodium): Int

  /** Decrypt the ciphertext, in an api-compatible way with libsodium authenticated encryption
    *
    * @param origOut the original message
    * @param ct the ciphertext
    * @param key the key
    * @return 0 if successful, any other number indicates unsuccessful
    */
  private[tsec] def sodiumDecrypt(origOut: Array[Byte], ct: CipherText[A], key: SodiumKey[A])(
      implicit S: ScalaSodium
  ): Int

  /** Decrypt the ciphertext, in an api-compatible way with libsodium authenticated encryption
    *
    * @param origOut the original message
    * @param ct the ciphertext
    * @param key the key
    * @return 0 if successful, any other number indicates unsuccessful
    */
  private[tsec] def sodiumDecryptDetached(
      origOut: Array[Byte],
      ct: CipherText[A],
      tagIn: AuthTag[A],
      key: SodiumKey[A]
  )(implicit S: ScalaSodium): Int

  /** Encrypt the plaintext using the nonce (in other words initialization vector)
    * in an api-compatible way with libsodium
    *
    * Mutates the cout array, same as libsodium
    *
    * @param cout ciphertext
    * @param pt plaintext
    * @param nonce Initialization vector
    * @param key the encryption key
    * @return 0 if successful, any other number means unsuccessful
    */
  private[tsec] def sodiumEncryptAAD(
      cout: Array[Byte],
      pt: PlainText,
      nonce: Array[Byte],
      key: SodiumKey[A],
      aad: AAD
  )(implicit S: ScalaSodium): Int

  /** Decrypt the ciphertext, in an api-compatible way with libsodium authenticated encryption
    *
    * @param origOut the original message
    * @param ct the ciphertext
    * @param key the key
    * @return 0 if successful, any other number indicates unsuccessful
    */
  private[tsec] def sodiumDecryptAAD(origOut: Array[Byte], ct: CipherText[A], key: SodiumKey[A], aad: AAD)(
      implicit S: ScalaSodium
  ): Int

  /** Encrypt the plaintext using the nonce (in other words initialization vector)
    * in an api-compatible way with libsodium
    *
    * Mutates the cout array, same as libsodium
    *
    * @param cout ciphertext
    * @param pt plaintext
    * @param nonce Initialization vector
    * @param key the encryption key
    * @return 0 if successful, any other number means unsuccessful
    */
  private[tsec] def sodiumEncryptDetachedAAD(
      cout: Array[Byte],
      tagOut: Array[Byte],
      pt: PlainText,
      nonce: Array[Byte],
      key: SodiumKey[A],
      aad: AAD
  )(implicit S: ScalaSodium): Int

  /** Decrypt the ciphertext, in an api-compatible way with libsodium authenticated encryption
    *
    * @param origOut the original message
    * @param ct the ciphertext
    * @param key the key
    * @return 0 if successful, any other number indicates unsuccessful
    */
  private[tsec] def sodiumDecryptDetachedAAD(
      origOut: Array[Byte],
      ct: CipherText[A],
      tagIn: AuthTag[A],
      key: SodiumKey[A],
      aad: AAD
  )(implicit S: ScalaSodium): Int

}
