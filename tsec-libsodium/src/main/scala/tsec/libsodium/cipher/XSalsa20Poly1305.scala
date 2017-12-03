package tsec.libsodium.cipher

import tsec.libsodium.ScalaSodium
import tsec.libsodium.cipher.internal.SodiumCipherPlatform

sealed trait XSalsa20Poly1305

object XSalsa20Poly1305 extends SodiumCipherPlatform[XSalsa20Poly1305] {

  def algorithm: String = "XSalsa20Poly1305"

  val nonceLen: Int = ScalaSodium.crypto_secretbox_xsalsa20poly1305_NONCEBYTES

  val keyLength: Int = ScalaSodium.crypto_secretbox_xsalsa20poly1305_KEYBYTES

  val macLen: Int = ScalaSodium.crypto_secretbox_xsalsa20poly1305_MACBYTES

  @inline private[tsec] def sodiumEncrypt(
      cout: Array[Byte],
      plaintext: PlainText,
      nonce: Array[Byte],
      key: SodiumKey[XSalsa20Poly1305]
  )(implicit S: ScalaSodium): Int =
    S.crypto_secretbox_easy(cout, plaintext, plaintext.length, nonce, key)

  @inline private[tsec] def sodiumDecrypt(
      origOut: Array[Byte],
      ct: SodiumCipherText[XSalsa20Poly1305],
      key: SodiumKey[XSalsa20Poly1305]
  )(implicit S: ScalaSodium): Int =
    S.crypto_secretbox_open_easy(origOut, ct.content, ct.content.length, ct.iv, key)

  @inline private[tsec] def sodiumEncryptDetached(
      cout: Array[Byte],
      tagOut: Array[Byte],
      pt: PlainText,
      nonce: Array[Byte],
      key: SodiumKey[XSalsa20Poly1305]
  )(implicit S: ScalaSodium): Int =
    S.crypto_secretbox_detached(cout, tagOut, pt, pt.length, nonce, key)

  @inline private[tsec] def sodiumDecryptDetached(
      origOut: Array[Byte],
      ct: SodiumCipherText[XSalsa20Poly1305],
      tagIn: AuthTag[XSalsa20Poly1305],
      key: SodiumKey[XSalsa20Poly1305]
  )(implicit S: ScalaSodium): Int =
    S.crypto_secretbox_open_detached(origOut, ct.content, tagIn, ct.content.length, ct.iv, key)
}
