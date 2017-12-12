package tsec.libsodium.cipher.internal

import tsec.libsodium.ScalaSodium
import tsec.libsodium.cipher._

trait SodiumAuthCipher[A]  {
  val nonceLen: Int
  val macLen: Int

  def algorithm: String

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

  /** Decrypt the ciphertext, in an api-compatible way with libsodium authenticated encryption
    *
    * @param origOut the original message
    * @param ct the ciphertext
    * @param key the key
    * @return 0 if successful, any other number indicates unsuccessful
    */
  private[tsec] def sodiumDecrypt(origOut: Array[Byte], ct: SodiumCipherText[A], key: SodiumKey[A])(
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
  private[tsec] def sodiumDecryptDetached(
    origOut: Array[Byte],
    ct: SodiumCipherText[A],
    tagIn: AuthTag[A],
    key: SodiumKey[A]
  )(implicit S: ScalaSodium): Int

}
