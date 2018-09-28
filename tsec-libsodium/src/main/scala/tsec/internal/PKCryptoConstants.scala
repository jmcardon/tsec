package tsec.internal

trait PKCryptoConstants {

  val crypto_box_curve25519xsalsa20poly1305_SEEDBYTES = 32

  val crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES = 32

  val crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES = 32

  val crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES = 32

  val crypto_box_curve25519xsalsa20poly1305_NONCEBYTES = 24

  val crypto_box_curve25519xsalsa20poly1305_MACBYTES = 16

  def crypto_box_SEEDBYTES = crypto_box_curve25519xsalsa20poly1305_SEEDBYTES

  def crypto_box_PUBLICKEYBYTES = crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES

  def crypto_box_SECRETKEYBYTES = crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES

  def crypto_box_NONCEBYTES = crypto_box_curve25519xsalsa20poly1305_NONCEBYTES

  def crypto_box_MACBYTES = crypto_box_curve25519xsalsa20poly1305_MACBYTES

  def crypto_box_BEFORENMBYTES = crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES

  def crypto_box_SEALBYTES = crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES

  val crypto_sign_ed25519_BYTES = 64

  val crypto_sign_ed25519_SEEDBYTES = 32

  val crypto_sign_ed25519_PUBLICKEYBYTES = 32

  val crypto_sign_ed25519_SECRETKEYBYTES = 64

  def crypto_sign_BYTES = crypto_sign_ed25519_BYTES

  def crypto_sign_SEEDBYTES = crypto_sign_ed25519_SEEDBYTES

  def crypto_sign_PUBLICKEYBYTES = crypto_sign_ed25519_PUBLICKEYBYTES

  def crypto_sign_SECRETKEYBYTES = crypto_sign_ed25519_SECRETKEYBYTES

}
