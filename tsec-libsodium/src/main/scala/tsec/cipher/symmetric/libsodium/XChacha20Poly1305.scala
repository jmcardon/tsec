package tsec.cipher.symmetric.libsodium

import tsec.ScalaSodium
import tsec.cipher.symmetric
import tsec.cipher.symmetric.libsodium.internal.SodiumCipherPlatform

sealed trait XChacha20Poly1305

object XChacha20Poly1305 extends SodiumCipherPlatform[XChacha20Poly1305] {
  val nonceLen: Int  = ScalaSodium.crypto_secretbox_xchacha20poly1305_NONCEBYTES
  val macLen: Int    = ScalaSodium.crypto_secretbox_xchacha20poly1305_MACBYTES
  val keyLength: Int = ScalaSodium.crypto_secretbox_xchacha20poly1305_KEYBYTES

  def algorithm: String = "XChacha20Poly1305"

  def sodiumEncrypt(cout: Array[Byte], pt: symmetric.PlainText, nonce: Array[Byte], key: SodiumKey[XChacha20Poly1305])(
      implicit S: ScalaSodium
  ): Int = S.crypto_secretbox_xchacha20poly1305_easy(cout, pt.content, pt.content.length, nonce, key)

  def sodiumDecrypt(origOut: Array[Byte], ct: SodiumCipherText[XChacha20Poly1305], key: SodiumKey[XChacha20Poly1305])(
      implicit S: ScalaSodium
  ): Int = S.crypto_secretbox_xchacha20poly1305_open_easy(origOut, ct.content, ct.content.length, ct.iv, key)

  def sodiumEncryptDetached(
      cout: Array[Byte],
      tagOut: Array[Byte],
      pt: symmetric.PlainText,
      nonce: Array[Byte],
      key: SodiumKey[XChacha20Poly1305]
  )(implicit S: ScalaSodium): Int =
    S.crypto_secretbox_xchacha20poly1305_detached(cout, tagOut, pt.content, pt.content.length, nonce, key)

  def sodiumDecryptDetached(
      origOut: Array[Byte],
      ct: SodiumCipherText[XChacha20Poly1305],
      tagIn: AuthTag[XChacha20Poly1305],
      key: SodiumKey[XChacha20Poly1305]
  )(implicit S: ScalaSodium): Int =
    S.crypto_secretbox_xchacha20poly1305_open_detached(origOut, ct.content, tagIn, ct.content.length, ct.iv, key)
}
