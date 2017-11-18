package tsec.cipher.symmetric.libsodium

import tsec.{ScalaSodium => Sodium}
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.libsodium.internal.SodiumCipherPlatform

sealed trait XSalsa20Poly1305

object XSalsa20Poly1305 extends SodiumCipherPlatform[XSalsa20Poly1305] {

  def algorithm: String = "XSalsa20Poly1305"

  val nonceLen: Int = Sodium.crypto_secretbox_xsalsa20poly1305_NONCEBYTES

  val keyLength: Int = Sodium.crypto_secretbox_xsalsa20poly1305_KEYBYTES

  val macLen: Int = Sodium.crypto_secretbox_xsalsa20poly1305_MACBYTES

  @inline def sodiumEncrypt(
      cout: Array[Byte],
      plaintext: PlainText,
      nonce: Array[Byte],
      key: SodiumKey[XSalsa20Poly1305]
  )(implicit S: Sodium): Int =
    S.crypto_secretbox_easy(cout, plaintext.content, plaintext.content.length, nonce, key)

  @inline def sodiumDecrypt(
      origOut: Array[Byte],
      ct: SodiumCipherText[XSalsa20Poly1305],
      key: SodiumKey[XSalsa20Poly1305]
  )(implicit S: Sodium): Int =
    S.crypto_secretbox_open_easy(origOut, ct.content, ct.content.length, ct.iv, key)

  @inline def sodiumEncryptDetached(
      cout: Array[Byte],
      tagOut: Array[Byte],
      pt: PlainText,
      nonce: Array[Byte],
      key: SodiumKey[XSalsa20Poly1305]
  )(implicit S: Sodium): Int =
    S.crypto_secretbox_detached(cout, tagOut, pt.content, pt.content.length, nonce, key)

  @inline def sodiumDecryptDetached(
      origOut: Array[Byte],
      ct: SodiumCipherText[XSalsa20Poly1305],
      tagIn: AuthTag[XSalsa20Poly1305],
      key: SodiumKey[XSalsa20Poly1305]
  )(implicit S: Sodium): Int =
    S.crypto_secretbox_open_detached(origOut, ct.content, tagIn, ct.content.length, ct.iv, key)
}
