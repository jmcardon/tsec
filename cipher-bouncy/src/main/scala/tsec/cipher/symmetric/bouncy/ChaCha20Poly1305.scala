package tsec.cipher.symmetric.bouncy

import java.security.MessageDigest
import java.util

import cats.effect.Sync
import org.bouncycastle.crypto.engines.ChaChaEngine
import org.bouncycastle.crypto.macs.Poly1305
import org.bouncycastle.crypto.params.{KeyParameter, ParametersWithIV}
import org.bouncycastle.util.Pack
import tsec.cipher._
import tsec.cipher.symmetric._
import tsec.common.ManagedRandom

trait ChaCha20Poly1305

object ChaCha20Poly1305 extends AEADAPI[ChaCha20Poly1305, BouncySecretKey] {

  private val SubkeyLen     = 32
  private val tagLen        = 16
  private val NonceLenBytes = 8

  def authEncryptor[F[_]](implicit F: Sync[F]): AADEncryptor[F, ChaCha20Poly1305, BouncySecretKey] = ???

  def defaultIvGen[F[_]](implicit F: Sync[F]): IvGen[F, ChaCha20Poly1305] =
    new IvGen[F, ChaCha20Poly1305] with ManagedRandom {

      def genIv: F[Iv[ChaCha20Poly1305]] =
        F.delay(genIvUnsafe)

      def genIvUnsafe: Iv[ChaCha20Poly1305] = {
        val nonce = new Array[Byte](NonceLenBytes)
        nextBytes(nonce)
        Iv[ChaCha20Poly1305](nonce)
      }
    }

  object impl {
    def unsafeEncrypt(
        plainText: PlainText,
        k: BouncySecretKey[ChaCha20Poly1305],
        iv: Iv[ChaCha20Poly1305],
        aad: AAD
    ): CipherText[ChaCha20Poly1305] =
      unsafeEncryptAAD(plainText, k, iv, AAD(Array.empty[Byte]))

    def unsafeEncryptAAD(
        plainText: PlainText,
        k: BouncySecretKey[ChaCha20Poly1305],
        iv: Iv[ChaCha20Poly1305],
        aad: AAD
    ): CipherText[ChaCha20Poly1305] = {
      val chacha20   = new ChaChaEngine(20)
      val poly1305   = new Poly1305()
      val ctOut      = RawCipherText[ChaCha20Poly1305](new Array[Byte](plainText.length + tagLen))
      val firstBlock = new Array[Byte](64)
      val ctLen      = Pack.longToLittleEndian(plainText.length & 0xFFFFFFFFL)
      val aadLen     = Pack.longToLittleEndian(aad.length & 0xFFFFFFFFL)

      chacha20.init(true, new ParametersWithIV(new KeyParameter(k), iv))
      chacha20.processBytes(firstBlock, 0, firstBlock.length, firstBlock, 0)
      val macKey = new KeyParameter(firstBlock, 0, SubkeyLen)
      util.Arrays.fill(firstBlock, 0.toByte)

      chacha20.processBytes(plainText, 0, plainText.length, ctOut, tagLen)
      poly1305.init(macKey)
      poly1305.update(aad, 0, aad.length)
      poly1305.update(aadLen, 0, ctLen.length)
      poly1305.update(ctOut, tagLen, plainText.length)
      poly1305.update(ctLen, 0, ctLen.length)
      poly1305.doFinal(ctOut, 0)
      CipherText(ctOut, iv)
    }

    def unsafeDecrypt(
        ct: CipherText[ChaCha20Poly1305],
        k: BouncySecretKey[ChaCha20Poly1305]
    ): PlainText = unsafeDecryptAAD(ct, k, AAD(Array.empty))

    def unsafeDecryptAAD(
        ct: CipherText[ChaCha20Poly1305],
        k: BouncySecretKey[ChaCha20Poly1305],
        aad: AAD
    ): PlainText = {
      val ctLen = ct.content.length - tagLen
      if (ctLen - tagLen < 1)
        throw CipherTextError("Ciphertext is 0 or less bytes")

      val chacha20   = new ChaChaEngine(20)
      val poly1305   = new Poly1305()
      val firstBlock = new Array[Byte](64)
      val out        = PlainText(new Array[Byte](ctLen))

      val ctLenBytes  = Pack.longToLittleEndian(ctLen & 0xFFFFFFFFL)
      val aadLen      = Pack.longToLittleEndian(aad.length & 0xFFFFFFFFL)
      val computedTag = new Array[Byte](tagLen)
      val oldTag      = new Array[Byte](tagLen)
      System.arraycopy(ct, 0, oldTag, 0, tagLen)

      chacha20.init(false, new ParametersWithIV(new KeyParameter(k), ct.nonce))
      chacha20.processBytes(firstBlock, 0, firstBlock.length, firstBlock, 0)
      val macKey = new KeyParameter(firstBlock, 0, SubkeyLen)
      util.Arrays.fill(firstBlock, 0.toByte)

      chacha20.processBytes(ct.content, tagLen, ctLen, out, 0)
      poly1305.init(macKey)
      poly1305.update(aad, 0, aad.length)
      poly1305.update(aadLen, 0, ctLenBytes.length)
      poly1305.update(ct.content, tagLen, ctLen)
      poly1305.update(ctLenBytes, 0, ctLenBytes.length)
      poly1305.doFinal(computedTag, 0)

      if (!MessageDigest.isEqual(computedTag, oldTag))
        throw AuthTagError("Tags do not match")

      PlainText(out)
    }

    def unsafeEncryptDetached(
        plainText: PlainText,
        k: BouncySecretKey[ChaCha20Poly1305],
        iv: Iv[ChaCha20Poly1305]
    ): (CipherText[ChaCha20Poly1305], AuthTag[ChaCha20Poly1305]) =
      unsafeEncryptDetachedAAD(plainText, k, iv, AAD(Array.empty[Byte]))

    def unsafeEncryptDetachedAAD(
        plainText: PlainText,
        k: BouncySecretKey[ChaCha20Poly1305],
        iv: Iv[ChaCha20Poly1305],
        aad: AAD
    ): (CipherText[ChaCha20Poly1305], AuthTag[ChaCha20Poly1305]) = {
      val chacha20   = new ChaChaEngine(20)
      val poly1305   = new Poly1305()
      val ctOut      = RawCipherText[ChaCha20Poly1305](new Array[Byte](plainText.length))
      val tagOut     = AuthTag[ChaCha20Poly1305](new Array[Byte](tagLen))
      val firstBlock = new Array[Byte](64)
      val ctLen      = Pack.longToLittleEndian(plainText.length & 0xFFFFFFFFL)
      val aadLen     = Pack.longToLittleEndian(aad.length & 0xFFFFFFFFL)

      chacha20.init(true, new ParametersWithIV(new KeyParameter(k), iv))
      chacha20.processBytes(firstBlock, 0, firstBlock.length, firstBlock, 0)
      val macKey = new KeyParameter(firstBlock, 0, SubkeyLen)
      util.Arrays.fill(firstBlock, 0.toByte)

      chacha20.processBytes(plainText, 0, plainText.length, ctOut, 0)
      poly1305.init(macKey)
      poly1305.update(aad, 0, aad.length)
      poly1305.update(aadLen, 0, ctLen.length)
      poly1305.update(ctOut, 0, plainText.length)
      poly1305.update(ctLen, 0, ctLen.length)
      poly1305.doFinal(tagOut, 0)
      (CipherText(ctOut, iv), tagOut)
    }

    def unsafeDecryptDetached(
        ct: CipherText[ChaCha20Poly1305],
        authTag: AuthTag[ChaCha20Poly1305],
        k: BouncySecretKey[ChaCha20Poly1305]
    ): PlainText = unsafeDecryptDetachedAAD(ct, authTag, k, AAD(Array.empty[Byte]))

    def unsafeDecryptDetachedAAD(
        ct: CipherText[ChaCha20Poly1305],
        authTag: AuthTag[ChaCha20Poly1305],
        k: BouncySecretKey[ChaCha20Poly1305],
        aad: AAD
    ): PlainText = {
      if (ct.content.length < 1)
        throw CipherTextError("Ciphertext is 0 or less bytes")

      val chacha20    = new ChaChaEngine(20)
      val poly1305    = new Poly1305()
      val firstBlock  = new Array[Byte](64)
      val out         = PlainText(new Array[Byte](ct.content.length))
      val ctLen       = Pack.longToLittleEndian(ct.content.length & 0xFFFFFFFFL)
      val aadLen      = Pack.longToLittleEndian(aad.length & 0xFFFFFFFFL)
      val computedTag = new Array[Byte](tagLen)

      chacha20.init(false, new ParametersWithIV(new KeyParameter(k), ct.nonce))
      chacha20.processBytes(firstBlock, 0, firstBlock.length, firstBlock, 0)
      val macKey = new KeyParameter(firstBlock, 0, SubkeyLen)
      util.Arrays.fill(firstBlock, 0.toByte)

      chacha20.processBytes(ct.content, 0, ct.content.length, out, 0)
      poly1305.init(macKey)
      poly1305.update(aad, 0, aad.length)
      poly1305.update(aadLen, 0, ctLen.length)
      poly1305.update(ct.content, 0, ct.content.length)
      poly1305.update(ctLen, 0, ctLen.length)
      poly1305.doFinal(computedTag, 0)

      if (!MessageDigest.isEqual(computedTag, authTag))
        throw AuthTagError("Tags do not match")

      PlainText(out)
    }

  }

}
