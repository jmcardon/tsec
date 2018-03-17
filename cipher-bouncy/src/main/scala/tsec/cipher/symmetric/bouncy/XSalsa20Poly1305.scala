package tsec.cipher.symmetric.bouncy

import java.security.MessageDigest

import cats.effect.Sync
import org.bouncycastle.crypto.engines.XSalsa20Engine
import org.bouncycastle.crypto.macs.Poly1305
import org.bouncycastle.crypto.params.{KeyParameter, ParametersWithIV}
import tsec.Bouncy
import tsec.cipher._
import tsec.cipher.symmetric.{IvGen, _}
import tsec.common.ManagedRandom
import tsec.keygen.symmetric.SymmetricKeyGen

/** https://tools.ietf.org/html/rfc7539#section-2.5
  * impl derived from:
  * https://cr.yp.to/snuffle/xsalsa-20081128.pdf
  * https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_secretbox/xsalsa20poly1305/secretbox_xsalsa20poly1305.c
  *
  */
trait XSalsa20Poly1305

object XSalsa20Poly1305 extends AuthCipherAPI[XSalsa20Poly1305, BouncySecretKey] {
  private val KeyLen        = 32
  private val tagLen        = 16
  private val NonceLenBytes = 24

  implicit def defaultKeyGen[F[_]](implicit F: Sync[F]): SymmetricKeyGen[F, XSalsa20Poly1305, BouncySecretKey] =
    new SymmetricKeyGen[F, XSalsa20Poly1305, BouncySecretKey] with ManagedRandom {
      def generateKey: F[BouncySecretKey[XSalsa20Poly1305]] = F.delay {
        val kBytes = new Array[Byte](KeyLen) //same as key len, 32 bytes
        nextBytes(kBytes)
        BouncySecretKey(kBytes)
      }

      def build(rawKey: Array[Byte]): F[BouncySecretKey[XSalsa20Poly1305]] =
        if (rawKey.length != KeyLen)
          F.raiseError(CipherKeyBuildError("Invalid key length"))
        else
          F.pure(BouncySecretKey(rawKey))
    }

  def defaultIvGen[F[_]](implicit F: Sync[F]): IvGen[F, XSalsa20Poly1305] =
    new IvGen[F, XSalsa20Poly1305] with ManagedRandom {

      def genIv: F[Iv[XSalsa20Poly1305]] =
        F.delay(genIvUnsafe)

      def genIvUnsafe: Iv[XSalsa20Poly1305] = {
        val nonce = new Array[Byte](NonceLenBytes)
        nextBytes(nonce)
        Iv[XSalsa20Poly1305](nonce)
      }
    }

  implicit def authEncryptor[F[_]](
      implicit F: Sync[F]
  ): AuthEncryptor[F, XSalsa20Poly1305, BouncySecretKey] =
    new AuthEncryptor[F, XSalsa20Poly1305, BouncySecretKey] {
      def encryptDetached(
          plainText: PlainText,
          key: BouncySecretKey[XSalsa20Poly1305],
          iv: Iv[XSalsa20Poly1305]
      ): F[(CipherText[XSalsa20Poly1305], AuthTag[XSalsa20Poly1305])] =
        F.delay(impl.unsafeEncryptDetached(plainText, key, iv))

      def decryptDetached(
          cipherText: CipherText[XSalsa20Poly1305],
          key: BouncySecretKey[XSalsa20Poly1305],
          authTag: AuthTag[XSalsa20Poly1305]
      ): F[PlainText] =
        F.delay(impl.unsafeDecryptDetached(cipherText, authTag, key))

      def encrypt(
          plainText: PlainText,
          key: BouncySecretKey[XSalsa20Poly1305],
          iv: Iv[XSalsa20Poly1305]
      ): F[CipherText[XSalsa20Poly1305]] =
        F.delay(impl.unsafeEncrypt(plainText, key, iv))

      def decrypt(cipherText: CipherText[XSalsa20Poly1305], key: BouncySecretKey[XSalsa20Poly1305]): F[PlainText] =
        F.delay(impl.unsafeDecrypt(cipherText, key))
    }

  object impl {
    def unsafeEncrypt(
        plainText: PlainText,
        k: BouncySecretKey[XSalsa20Poly1305],
        iv: Iv[XSalsa20Poly1305]
    ): CipherText[XSalsa20Poly1305] = {
      val xsalsa20 = new XSalsa20Engine()
      val poly1305 = new Poly1305()
      val MacKey   = new Array[Byte](KeyLen)
      val out      = RawCipherText[XSalsa20Poly1305](new Array[Byte](plainText.length + tagLen))

      xsalsa20.init(true, new ParametersWithIV(new KeyParameter(k), iv))
      xsalsa20.processBytes(MacKey, 0, KeyLen, MacKey, 0)
      xsalsa20.processBytes(plainText, 0, plainText.length, out, tagLen)
      poly1305.init(new KeyParameter(MacKey))
      poly1305.update(out, tagLen, plainText.length)
      poly1305.doFinal(out, 0)
      CipherText(out, iv)
    }

    def unsafeDecrypt(
        ct: CipherText[XSalsa20Poly1305],
        k: BouncySecretKey[XSalsa20Poly1305]
    ): PlainText = {
      if (ct.content.length < tagLen + 1)
        throw CipherTextError("Ciphertext is 0 or less bytes")

      val xsalsa20 = new XSalsa20Engine()
      val poly1305 = new Poly1305()
      val subkey   = new Array[Byte](KeyLen)
      val out      = PlainText(new Array[Byte](ct.content.length - tagLen))
      val inTag    = new Array[Byte](tagLen)
      System.arraycopy(ct.content, 0, inTag, 0, tagLen)

      val computedTag = new Array[Byte](tagLen)

      xsalsa20.init(false, new ParametersWithIV(new KeyParameter(k), ct.nonce))
      xsalsa20.processBytes(subkey, 0, KeyLen, subkey, 0)
      xsalsa20.processBytes(ct.content, tagLen, ct.content.length - tagLen, out, 0)
      poly1305.init(new KeyParameter(subkey))
      poly1305.update(ct.content, tagLen, ct.content.length - tagLen)
      poly1305.doFinal(computedTag, 0)

      if (!MessageDigest.isEqual(computedTag, inTag))
        throw AuthTagError("Tags do not match")

      PlainText(out)
    }

    def unsafeEncryptDetached(
        plainText: PlainText,
        k: BouncySecretKey[XSalsa20Poly1305],
        iv: Iv[XSalsa20Poly1305]
    ): (CipherText[XSalsa20Poly1305], AuthTag[XSalsa20Poly1305]) = {
      val xsalsa20 = new XSalsa20Engine()
      val poly1305 = new Poly1305()
      val subkey   = new Array[Byte](KeyLen)
      val out      = RawCipherText[XSalsa20Poly1305](new Array[Byte](plainText.length))
      val tag      = AuthTag[XSalsa20Poly1305](new Array[Byte](tagLen))

      xsalsa20.init(true, new ParametersWithIV(new KeyParameter(k), iv))
      xsalsa20.processBytes(subkey, 0, KeyLen, subkey, 0)
      xsalsa20.processBytes(plainText, 0, plainText.length, out, 0)
      poly1305.init(new KeyParameter(subkey))
      poly1305.update(out, 0, plainText.length)
      poly1305.doFinal(tag, 0)
      (CipherText(out, iv), tag)
    }

    def unsafeDecryptDetached(
        ct: CipherText[XSalsa20Poly1305],
        authTag: AuthTag[XSalsa20Poly1305],
        k: BouncySecretKey[XSalsa20Poly1305]
    ): PlainText = {
      if (ct.content.length < 1)
        throw CipherTextError("Ciphertext is 0 or less bytes")

      val xsalsa20 = new XSalsa20Engine()
      val poly1305 = new Poly1305()
      val subkey   = new Array[Byte](KeyLen)
      val out      = PlainText(new Array[Byte](ct.content.length))

      val computedTag = new Array[Byte](tagLen)

      xsalsa20.init(false, new ParametersWithIV(new KeyParameter(k), ct.nonce))
      xsalsa20.processBytes(subkey, 0, KeyLen, subkey, 0)
      xsalsa20.processBytes(ct.content, 0, ct.content.length, out, 0)
      poly1305.init(new KeyParameter(subkey))
      poly1305.update(ct.content, 0, ct.content.length)
      poly1305.doFinal(computedTag, 0)

      if (!MessageDigest.isEqual(computedTag, authTag))
        throw AuthTagError("Tags do not match")

      PlainText(out)
    }

  }

}
