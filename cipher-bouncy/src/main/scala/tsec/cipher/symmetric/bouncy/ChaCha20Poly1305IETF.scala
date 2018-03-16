package tsec.cipher.symmetric.bouncy

import java.security.MessageDigest
import java.util

import cats.effect.Sync
import org.bouncycastle.crypto.macs.Poly1305
import org.bouncycastle.crypto.params.{KeyParameter, ParametersWithIV}
import org.bouncycastle.util.Pack
import tsec.cipher._
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.bouncy.internal.ChaCha20IETFEngine
import tsec.common.ManagedRandom
import tsec.keygen.symmetric.SymmetricKeyGen

sealed trait ChaCha20Poly1305IETF

object ChaCha20Poly1305IETF {
  private val KeyLen        = 32
  private val TagLen        = 16
  private val NonceLenBytes = 12
  private val BytePadding   = new Array[Byte](16)

  def defaultIvGen[F[_]](implicit F: Sync[F]): IvGen[F, ChaCha20Poly1305IETF] =
    new IvGen[F, ChaCha20Poly1305IETF] with ManagedRandom {

      def genIv: F[Iv[ChaCha20Poly1305IETF]] =
        F.delay(genIvUnsafe)

      def genIvUnsafe: Iv[ChaCha20Poly1305IETF] = {
        val nonce = new Array[Byte](NonceLenBytes)
        nextBytes(nonce)
        Iv[ChaCha20Poly1305IETF](nonce)
      }
    }

  implicit def defaultKeyGen[F[_]](implicit F: Sync[F]): SymmetricKeyGen[F, ChaCha20Poly1305IETF, BouncySecretKey] =
    new SymmetricKeyGen[F, ChaCha20Poly1305IETF, BouncySecretKey] with ManagedRandom {
      def generateKey: F[BouncySecretKey[ChaCha20Poly1305IETF]] = F.delay {
        val kBytes = new Array[Byte](KeyLen) //same as key len, 32 bytes
        nextBytes(kBytes)
        BouncySecretKey(kBytes)
      }

      def build(rawKey: Array[Byte]): F[BouncySecretKey[ChaCha20Poly1305IETF]] =
        if (rawKey.length != KeyLen)
          F.raiseError(CipherKeyBuildError("Invalid key length"))
        else
          F.pure(BouncySecretKey(rawKey))
    }

  implicit def authEncryptor[F[_]](
      implicit F: Sync[F]
  ): AADEncryptor[F, ChaCha20Poly1305IETF, BouncySecretKey] =
    new AADEncryptor[F, ChaCha20Poly1305IETF, BouncySecretKey] {
      def encryptWithAAD(
          plainText: PlainText,
          key: BouncySecretKey[ChaCha20Poly1305IETF],
          iv: Iv[ChaCha20Poly1305IETF],
          aad: AAD
      ): F[CipherText[ChaCha20Poly1305IETF]] =
        F.delay(impl.unsafeEncryptAAD(plainText, key, iv, aad))

      def encryptWithAADDetached(
          plainText: PlainText,
          key: BouncySecretKey[ChaCha20Poly1305IETF],
          iv: Iv[ChaCha20Poly1305IETF],
          aad: AAD
      ): F[(CipherText[ChaCha20Poly1305IETF], AuthTag[ChaCha20Poly1305IETF])] =
        F.delay(impl.unsafeEncryptDetachedAAD(plainText, key, iv, aad))

      def decryptWithAAD(
          cipherText: CipherText[ChaCha20Poly1305IETF],
          key: BouncySecretKey[ChaCha20Poly1305IETF],
          aad: AAD
      ): F[PlainText] =
        F.delay(impl.unsafeDecryptAAD(cipherText, key, aad))

      def decryptWithAADDetached(
          cipherText: CipherText[ChaCha20Poly1305IETF],
          key: BouncySecretKey[ChaCha20Poly1305IETF],
          aad: AAD,
          authTag: AuthTag[ChaCha20Poly1305IETF]
      ): F[PlainText] =
        F.delay(impl.unsafeDecryptDetachedAAD(cipherText, authTag, key, aad))

      def encryptDetached(
          plainText: PlainText,
          key: BouncySecretKey[ChaCha20Poly1305IETF],
          iv: Iv[ChaCha20Poly1305IETF]
      ): F[(CipherText[ChaCha20Poly1305IETF], AuthTag[ChaCha20Poly1305IETF])] =
        F.delay(impl.unsafeEncryptDetached(plainText, key, iv))

      def decryptDetached(
          cipherText: CipherText[ChaCha20Poly1305IETF],
          key: BouncySecretKey[ChaCha20Poly1305IETF],
          authTag: AuthTag[ChaCha20Poly1305IETF]
      ): F[PlainText] =
        F.delay(impl.unsafeDecryptDetached(cipherText, authTag, key))

      def encrypt(
          plainText: PlainText,
          key: BouncySecretKey[ChaCha20Poly1305IETF],
          iv: Iv[ChaCha20Poly1305IETF]
      ): F[CipherText[ChaCha20Poly1305IETF]] =
        F.delay(impl.unsafeEncrypt(plainText, key, iv))

      def decrypt(cipherText: CipherText[ChaCha20Poly1305IETF], key: BouncySecretKey[ChaCha20Poly1305IETF]): F[PlainText] =
        F.delay(impl.unsafeDecrypt(cipherText, key))
    }

  object impl {
    def unsafeEncrypt(
        plainText: PlainText,
        k: BouncySecretKey[ChaCha20Poly1305IETF],
        iv: Iv[ChaCha20Poly1305IETF]
    ): CipherText[ChaCha20Poly1305IETF] =
      unsafeEncryptAAD(plainText, k, iv, AAD(Array.empty[Byte]))

    def unsafeEncryptAAD(
        plainText: PlainText,
        k: BouncySecretKey[ChaCha20Poly1305IETF],
        iv: Iv[ChaCha20Poly1305IETF],
        aad: AAD
    ): CipherText[ChaCha20Poly1305IETF] = {
      val chacha20   = new ChaCha20IETFEngine()
      val poly1305   = new Poly1305()
      val ctOut      = RawCipherText[ChaCha20Poly1305IETF](new Array[Byte](plainText.length + TagLen))
      val firstBlock = new Array[Byte](64)
      val ctLen      = Pack.longToLittleEndian(plainText.length & 0xFFFFFFFFL)
      val aadLen     = Pack.longToLittleEndian(aad.length & 0xFFFFFFFFL)

      chacha20.initialize(new ParametersWithIV(new KeyParameter(k), iv))
      chacha20.processBytes(firstBlock, 0, firstBlock.length, firstBlock, 0)
      val macKey = new KeyParameter(firstBlock, 0, KeyLen)
      util.Arrays.fill(firstBlock, 0.toByte)

      chacha20.processBytes(plainText, 0, plainText.length, ctOut, 0)
      poly1305.init(macKey)
      poly1305.update(aad, 0, aad.length)
      poly1305.update(BytePadding, 0, (0x10 - aad.length) & 0xF)
      poly1305.update(ctOut, 0, plainText.length)
      poly1305.update(BytePadding, 0, (0x10 - plainText.length) & 0xF)
      poly1305.update(aadLen, 0, ctLen.length)
      poly1305.update(ctLen, 0, ctLen.length)
      poly1305.doFinal(ctOut, plainText.length)
      CipherText(ctOut, iv)
    }

    def unsafeEncryptDetached(
        plainText: PlainText,
        k: BouncySecretKey[ChaCha20Poly1305IETF],
        iv: Iv[ChaCha20Poly1305IETF]
    ): (CipherText[ChaCha20Poly1305IETF], AuthTag[ChaCha20Poly1305IETF]) =
      unsafeEncryptDetachedAAD(plainText, k, iv, AAD(Array.empty[Byte]))

    def unsafeEncryptDetachedAAD(
        plainText: PlainText,
        k: BouncySecretKey[ChaCha20Poly1305IETF],
        iv: Iv[ChaCha20Poly1305IETF],
        aad: AAD
    ): (CipherText[ChaCha20Poly1305IETF], AuthTag[ChaCha20Poly1305IETF]) = {
      val chacha20   = new ChaCha20IETFEngine()
      val poly1305   = new Poly1305()
      val ctOut      = RawCipherText[ChaCha20Poly1305IETF](new Array[Byte](plainText.length))
      val tagOut     = AuthTag[ChaCha20Poly1305IETF](new Array[Byte](TagLen))
      val firstBlock = new Array[Byte](64)
      val ctLen      = Pack.longToLittleEndian(plainText.length & 0xFFFFFFFFL)
      val aadLen     = Pack.longToLittleEndian(aad.length & 0xFFFFFFFFL)
      val params     = new ParametersWithIV(new KeyParameter(k), iv)
      chacha20.initialize(params)
      chacha20.processBytes(firstBlock, 0, firstBlock.length, firstBlock, 0)
      val macKey = new KeyParameter(firstBlock, 0, KeyLen)
      util.Arrays.fill(firstBlock, 0.toByte)

      chacha20.processBytes(plainText, 0, plainText.length, ctOut, 0)
      poly1305.init(macKey)
      poly1305.update(aad, 0, aad.length)
      poly1305.update(BytePadding, 0, (0x10 - aad.length) & 0xF)
      poly1305.update(ctOut, 0, plainText.length)
      poly1305.update(BytePadding, 0, (0x10 - plainText.length) & 0xF)
      poly1305.update(aadLen, 0, ctLen.length)
      poly1305.update(ctLen, 0, ctLen.length)
      poly1305.doFinal(tagOut, 0)
      (CipherText(ctOut, iv), tagOut)
    }

    def unsafeDecrypt(
        ct: CipherText[ChaCha20Poly1305IETF],
        k: BouncySecretKey[ChaCha20Poly1305IETF]
    ): PlainText = unsafeDecryptAAD(ct, k, AAD(Array.empty))

    def unsafeDecryptAAD(
        ct: CipherText[ChaCha20Poly1305IETF],
        k: BouncySecretKey[ChaCha20Poly1305IETF],
        aad: AAD
    ): PlainText = {
      val ctLen = ct.content.length - TagLen
      if (ctLen < 1)
        throw CipherTextError("Ciphertext is 0 or less bytes")

      val chacha20    = new ChaCha20IETFEngine()
      val poly1305    = new Poly1305()
      val firstBlock  = new Array[Byte](64)
      val out         = PlainText(new Array[Byte](ct.content.length - TagLen))
      val ctLenBytes  = Pack.longToLittleEndian(ctLen & 0xFFFFFFFFL)
      val aadLen      = Pack.longToLittleEndian(aad.length & 0xFFFFFFFFL)
      val computedTag = new Array[Byte](TagLen)
      val oldTag      = new Array[Byte](TagLen)
      System.arraycopy(ct.content, ctLen, oldTag, 0, TagLen)

      chacha20.initialize(new ParametersWithIV(new KeyParameter(k), ct.nonce))
      chacha20.processBytes(firstBlock, 0, firstBlock.length, firstBlock, 0)
      val macKey = new KeyParameter(firstBlock, 0, KeyLen)
      util.Arrays.fill(firstBlock, 0.toByte)

      chacha20.processBytes(ct.content, 0, ctLen, out, 0)
      poly1305.init(macKey)
      poly1305.update(aad, 0, aad.length)
      poly1305.update(BytePadding, 0, (0x10 - aad.length) & 0xF)
      poly1305.update(ct.content, 0, ctLen)
      poly1305.update(BytePadding, 0, (0x10 - ctLen) & 0xF)
      poly1305.update(aadLen, 0, ctLenBytes.length)
      poly1305.update(ctLenBytes, 0, ctLenBytes.length)
      poly1305.doFinal(computedTag, 0)

      if (!MessageDigest.isEqual(computedTag, oldTag))
        throw AuthTagError("Tags do not match")

      PlainText(out)
    }

    def unsafeDecryptDetached(
        ct: CipherText[ChaCha20Poly1305IETF],
        authTag: AuthTag[ChaCha20Poly1305IETF],
        k: BouncySecretKey[ChaCha20Poly1305IETF]
    ): PlainText = unsafeDecryptDetachedAAD(ct, authTag, k, AAD(Array.empty[Byte]))

    def unsafeDecryptDetachedAAD(
        ct: CipherText[ChaCha20Poly1305IETF],
        authTag: AuthTag[ChaCha20Poly1305IETF],
        k: BouncySecretKey[ChaCha20Poly1305IETF],
        aad: AAD
    ): PlainText = {
      if (ct.content.length < 1)
        throw CipherTextError("Ciphertext is 0 or less bytes")

      val chacha20    = new ChaCha20IETFEngine()
      val poly1305    = new Poly1305()
      val firstBlock  = new Array[Byte](64)
      val out         = PlainText(new Array[Byte](ct.content.length))
      val ctLen       = Pack.longToLittleEndian(ct.content.length & 0xFFFFFFFFL)
      val aadLen      = Pack.longToLittleEndian(aad.length & 0xFFFFFFFFL)
      val computedTag = new Array[Byte](TagLen)

      chacha20.initialize(new ParametersWithIV(new KeyParameter(k), ct.nonce))
      chacha20.processBytes(firstBlock, 0, firstBlock.length, firstBlock, 0)
      val macKey = new KeyParameter(firstBlock, 0, KeyLen)
      util.Arrays.fill(firstBlock, 0.toByte)

      chacha20.processBytes(ct.content, 0, ct.content.length, out, 0)
      poly1305.init(macKey)
      poly1305.update(aad, 0, aad.length)
      poly1305.update(BytePadding, 0, (0x10 - aad.length) & 0xF)
      poly1305.update(ct.content, 0, ct.content.length)
      poly1305.update(BytePadding, 0, (0x10 - ct.content.length) & 0xF)
      poly1305.update(aadLen, 0, ctLen.length)
      poly1305.update(ctLen, 0, ctLen.length)
      poly1305.doFinal(computedTag, 0)

      if (!MessageDigest.isEqual(computedTag, authTag))
        throw AuthTagError("Tags do not match")

      PlainText(out)
    }

  }

}
