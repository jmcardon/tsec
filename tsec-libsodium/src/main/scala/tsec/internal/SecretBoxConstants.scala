package tsec.internal


/** Constants defined in:
  * https://github.com/jedisct1/libsodium/blob/master/src/libsodium/include/sodium/crypto_secretbox_xsalsa20poly1305.h#L29
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
