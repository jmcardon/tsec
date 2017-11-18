package tsec.internal

import jnr.ffi.LibraryLoader
import jnr.ffi.Platform
import jnr.ffi.annotations.In
import jnr.ffi.annotations.Out
import jnr.ffi.byref.LongLongByReference
import jnr.ffi.types.u_int64_t
import jnr.ffi.types.u_int8_t
import jnr.ffi.types.size_t

trait SecretBox {

  /** Same as secretbox_easy i think
    *
    */
  def crypto_secretbox(
      @Out ciphertext: Array[Byte],
      @In message: Array[Byte],
      @In @u_int8_t messageLen: Long,
      @In nonce: Array[Byte],
      @In key: Array[Byte]
  ): Int

  /** Same as secretbox_open
    *
    */
  def crypto_secretbox_open(
      @Out plaintext: Array[Byte],
      @In cipherText: Array[Byte],
      @In @u_int8_t cLen: Long,
      @In nonce: Array[Byte],
      @In key: Array[Byte]
  ): Int

  /** Secret key authenticated encryption.
    * note: c should be at least crypto_secretbox_MACBYTES + mlen bytes long.
    *
    */
  def crypto_secretbox_easy(
      @Out ciphertext: Array[Byte],
      @In message: Array[Byte],
      @In @u_int8_t messageLen: Long,
      @In nonce: Array[Byte],
      @In key: Array[Byte]
  ): Int

  /** Decrypt the message
    * note: CLen is the length of the authentication tag + the encryped message
    */
  def crypto_secretbox_open_easy(
      @Out plaintext: Array[Byte],
      @In cipherText: Array[Byte],
      @In @u_int8_t cLen: Long,
      @In nonce: Array[Byte],
      @In key: Array[Byte]
  ): Int

  /** Encrypt the message, but
    * with a mac stored safely somewhere else
    * -1 if fail, 0 on success
    *
    * @param ciphertext
    * @param mac
    * @param message
    * @param messageLen
    * @param nonce
    * @param key
    * @return
    */
  def crypto_secretbox_detached(
      @Out ciphertext: Array[Byte],
      @Out mac: Array[Byte],
      @In message: Array[Byte],
      @In @u_int8_t messageLen: Long,
      @In nonce: Array[Byte],
      @In key: Array[Byte]
  ): Int

  /** Decrypt the message, separate MAC
    * -1 if fail, 0 on success
    *
    */
  def crypto_secretbox_open_detached(
      @Out plaintext: Array[Byte],
      @In cipherText: Array[Byte],
      @In mac: Array[Byte],
      @In @u_int8_t cLen: Long,
      @In nonce: Array[Byte],
      @In key: Array[Byte]
  ): Int

  /** Generate a random key of length
    * crypto_secretbox_KEYBYTES
    *
    * -1 if fail, 0 on success.
    *
    * @param bytes
    */
  def crypto_secretbox_keygen(@Out bytes: Array[Byte]): Unit

  /** Specific function **/
  /** Secret key authenticated encryption.
    * note: c should be at least crypto_secretbox_MACBYTES + mlen bytes long.
    *
    */
  def crypto_secretbox_xsalsa20poly1305(
      @Out ciphertext: Array[Byte],
      @In message: Array[Byte],
      @In @u_int8_t messageLen: Long,
      @In nonce: Array[Byte],
      @In key: Array[Byte]
  ): Int

  /** Decrypt the message
    * note: CLen is the length of the authentication tag + the encryped message
    */
  def crypto_secretbox_xsalsa20poly1305_open(
      @Out plaintext: Array[Byte],
      @In cipherText: Array[Byte],
      @In @u_int8_t cLen: Long,
      @In nonce: Array[Byte],
      @In key: Array[Byte]
  ): Int

  /** Secret key authenticated encryption.
    * note: c should be at least crypto_secretbox_MACBYTES + mlen bytes long.
    *
    */
  def crypto_secretbox_xchacha20poly1305_easy(
      @Out ciphertext: Array[Byte],
      @In message: Array[Byte],
      @In @u_int8_t messageLen: Long,
      @In nonce: Array[Byte],
      @In key: Array[Byte]
  ): Int

  /** Decrypt the message
    * note: CLen is the length of the authentication tag + the encryped message
    */
  def crypto_secretbox_xchacha20poly1305_open_easy(
      @Out plaintext: Array[Byte],
      @In cipherText: Array[Byte],
      @In @u_int8_t cLen: Long,
      @In nonce: Array[Byte],
      @In key: Array[Byte]
  ): Int

  /** Encrypt the message, but
    * with a mac stored safely somewhere else
    * -1 if fail, 0 on success
    *
    * @param ciphertext
    * @param mac
    * @param message
    * @param messageLen
    * @param nonce
    * @param key
    * @return
    */
  def crypto_secretbox_xchacha20poly1305_detached(
      @Out ciphertext: Array[Byte],
      @Out mac: Array[Byte],
      @In message: Array[Byte],
      @In @u_int8_t messageLen: Long,
      @In nonce: Array[Byte],
      @In key: Array[Byte]
  ): Int

  /** Decrypt the message, separate MAC
    * -1 if fail, 0 on success
    *
    */
  def crypto_secretbox_xchacha20poly1305_open_detached(
      @Out plaintext: Array[Byte],
      @In cipherText: Array[Byte],
      @In mac: Array[Byte],
      @In @u_int8_t cLen: Long,
      @In nonce: Array[Byte],
      @In key: Array[Byte]
  ): Int

}

/** Constants defined in:
  * https://github.com/jedisct1/libsodium/blob/master/src/libsodium/include/sodium/crypto_secretbox_xsalsa20poly1305.h#L29
  *
  *
  */
private[tsec] trait SecretBoxConstants {

  val crypto_secretbox_xsalsa20poly1305_KEYBYTES = 32

  val crypto_secretbox_xsalsa20poly1305_NONCEBYTES = 24

  val crypto_secretbox_xsalsa20poly1305_MACBYTES = 16

  /* Only for the libsodium API - The NaCl compatibility API would require BOXZEROBYTES extra bytes */
  val crypto_secretbox_xsalsa20poly1305_MESSAGEBYTES_MAX
    : Long = Long.MaxValue - crypto_secretbox_xsalsa20poly1305_MACBYTES

  val crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES = 16

  val crypto_secretbox_xsalsa20poly1305_ZEROBYTES: Long =
    crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES + crypto_secretbox_xsalsa20poly1305_MACBYTES

  val crypto_secretbox_xchacha20poly1305_KEYBYTES = 32

  val crypto_secretbox_xchacha20poly1305_NONCEBYTES = 24

  val crypto_secretbox_xchacha20poly1305_MACBYTES = 16

  val crypto_secretbox_xchacha20poly1305_MESSAGEBYTES_MAX =
    Long.MaxValue - crypto_secretbox_xchacha20poly1305_MACBYTES

  def crypto_secretbox_KEYBYTES: Long = crypto_secretbox_xsalsa20poly1305_KEYBYTES

  def crypto_secretbox_NONCEBYTES: Long = crypto_secretbox_xsalsa20poly1305_NONCEBYTES

  def crypto_secretbox_MACBYTES: Long = crypto_secretbox_xsalsa20poly1305_MACBYTES

  def crypto_secretbox_PRIMITIVE: String = "xsalsa20poly1305"

  def crypto_secretbox_MESSAGEBYTES_MAX: Long = crypto_secretbox_xsalsa20poly1305_MESSAGEBYTES_MAX

  def crypto_secretbox_ZEROBYTES: Long = crypto_secretbox_xsalsa20poly1305_ZEROBYTES

  def crypto_secretbox_BOXZEROBYTES: Int = crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES

}
