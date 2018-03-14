package tsec.cipher.asymmetric.libsodium

import cats.effect.Sync
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.libsodium.SodiumCipherError._
import tsec.libsodium.ScalaSodium

sealed trait CryptoBox

object CryptoBox {
  val seedLen      = ScalaSodium.crypto_box_SEEDBYTES
  val pubKLen      = ScalaSodium.crypto_box_PUBLICKEYBYTES
  val privKLen     = ScalaSodium.crypto_box_SECRETKEYBYTES
  val macLen       = ScalaSodium.crypto_box_MACBYTES
  val nonceLen     = ScalaSodium.crypto_box_NONCEBYTES
  val sharedKenLen = ScalaSodium.crypto_box_BEFORENMBYTES

  def generateKeyPair[F[_]](implicit F: Sync[F], S: ScalaSodium): F[SodiumKeyPair[CryptoBox]] = F.delay {
    val pubk  = PublicKey[CryptoBox](new Array[Byte](pubKLen))
    val privK = PrivateKey[CryptoBox](new Array[Byte](privKLen))
    S.crypto_box_keypair(pubk, privK)
    SodiumKeyPair(pubk, privK)
  }

  def encrypt[F[_]](raw: PlainText, recipientPub: PublicKey[CryptoBox], sender: PrivateKey[CryptoBox])(
      implicit F: Sync[F],
      S: ScalaSodium
  ): F[CipherText[CryptoBox]] = F.delay {
    val out   = RawCipherText[CryptoBox](new Array[Byte](raw.length + macLen))
    val nonce = Iv[CryptoBox](ScalaSodium.randomBytesUnsafe(nonceLen))
    if (S.crypto_box_easy(out, raw, raw.length, nonce, recipientPub, sender) != 0)
      throw EncryptError("Invalid encryption info")
    CipherText[CryptoBox](out, nonce)
  }

  def decrypt[F[_]](
      cipherText: CipherText[CryptoBox],
      senderPub: PublicKey[CryptoBox],
      recipientPriv: PrivateKey[CryptoBox]
  )(implicit F: Sync[F], S: ScalaSodium): F[PlainText] = F.delay {
    val outLen = cipherText.content.length - macLen
    if (outLen < 0)
      throw DecryptError("Invalid Ciphertext")

    val out = new Array[Byte](outLen)
    if (S.crypto_box_open_easy(
          out,
          cipherText.content,
          cipherText.content.length,
          cipherText.nonce,
          senderPub,
          recipientPriv
        ) != 0) throw DecryptError("Invalid decryption parameters")

    PlainText(out)
  }

  def encryptDetached[F[_]](raw: PlainText, recipientPub: PublicKey[CryptoBox], sender: PrivateKey[CryptoBox])(
      implicit F: Sync[F],
      S: ScalaSodium
  ): F[(CipherText[CryptoBox], PKAuthTag[CryptoBox])] = F.delay {
    val out   = RawCipherText[CryptoBox](new Array[Byte](raw.length))
    val mac   = new Array[Byte](macLen)
    val nonce = Iv[CryptoBox](ScalaSodium.randomBytesUnsafe(nonceLen))
    if (S.crypto_box_detached(out, mac, raw, raw.length, nonce, recipientPub, sender) != 0)
      throw EncryptError("Invalid encryption info")
    (CipherText[CryptoBox](out, nonce), PKAuthTag[CryptoBox](mac))
  }

  def decryptDetached[F[_]](
      cipherText: CipherText[CryptoBox],
      tag: PKAuthTag[CryptoBox],
      senderPub: PublicKey[CryptoBox],
      recipientPriv: PrivateKey[CryptoBox]
  )(implicit F: Sync[F], S: ScalaSodium): F[PlainText] = F.delay {

    val out = new Array[Byte](cipherText.content.length)
    if (S.crypto_box_open_detached(
          out,
          cipherText.content,
          tag,
          cipherText.content.length,
          cipherText.nonce,
          senderPub,
          recipientPriv
        ) != 0) throw DecryptError("Invalid decryption parameters")

    PlainText(out)
  }

  def precalcSharedKey[F[_]](pubK: PublicKey[CryptoBox], privK: PrivateKey[CryptoBox])(
      implicit F: Sync[F],
      S: ScalaSodium
  ): F[SharedKey[CryptoBox]] = F.delay {
    val nmBytes = new Array[Byte](sharedKenLen)
    S.crypto_box_beforenm(nmBytes, pubK, privK)
    SharedKey[CryptoBox](nmBytes)
  }

  def encryptPrecalc[F[_]](raw: PlainText, precalc: SharedKey[CryptoBox])(
      implicit F: Sync[F],
      S: ScalaSodium
  ): F[CipherText[CryptoBox]] = F.delay {
    val out   = RawCipherText[CryptoBox](new Array[Byte](raw.length + macLen))
    val nonce = Iv[CryptoBox](ScalaSodium.randomBytesUnsafe(nonceLen))
    if (S.crypto_box_easy_afternm(out, raw, raw.length, nonce, precalc) != 0)
      throw EncryptError("Invalid encryption info")
    CipherText[CryptoBox](out, nonce)
  }

  def decryptPrecalc[F[_]](
      cipherText: CipherText[CryptoBox],
      precalc: SharedKey[CryptoBox]
  )(implicit F: Sync[F], S: ScalaSodium): F[PlainText] = F.delay {
    val outLen = cipherText.content.length - macLen
    if (outLen < 0)
      throw DecryptError("Invalid Ciphertext")

    val out = new Array[Byte](outLen)
    if (S.crypto_box_open_easy_afternm(
          out,
          cipherText.content,
          cipherText.content.length,
          cipherText.nonce,
          precalc
        ) != 0) throw DecryptError("Invalid decryption parameters")

    PlainText(out)
  }

  def encryptPrecalcDetached[F[_]](
      raw: PlainText,
      precalc: SharedKey[CryptoBox]
  )(implicit F: Sync[F], S: ScalaSodium): F[(CipherText[CryptoBox], PKAuthTag[CryptoBox])] = F.delay {
    val out   = RawCipherText[CryptoBox](new Array[Byte](raw.length))
    val mac   = new Array[Byte](macLen)
    val nonce = Iv[CryptoBox](ScalaSodium.randomBytesUnsafe(nonceLen))
    if (S.crypto_box_detached_afternm(out, mac, raw, raw.length, nonce, precalc) != 0)
      throw EncryptError("Invalid encryption info")
    (CipherText[CryptoBox](out, nonce), PKAuthTag[CryptoBox](mac))
  }

  def decryptPrecalcDetached[F[_]](
      cipherText: CipherText[CryptoBox],
      tag: PKAuthTag[CryptoBox],
      precalc: SharedKey[CryptoBox]
  )(implicit F: Sync[F], S: ScalaSodium): F[PlainText] = F.delay {
    val out = new Array[Byte](cipherText.content.length)
    if (S.crypto_box_open_detached_afternm(
          out,
          cipherText.content,
          tag,
          cipherText.content.length,
          cipherText.nonce,
          precalc
        ) != 0) throw DecryptError("Invalid decryption parameters")

    PlainText(out)
  }

}
