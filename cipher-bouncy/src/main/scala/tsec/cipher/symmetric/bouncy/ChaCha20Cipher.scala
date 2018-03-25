package tsec.cipher.symmetric.bouncy

import java.security.MessageDigest
import java.util

import cats.effect.Sync
import org.bouncycastle.crypto.StreamCipher
import org.bouncycastle.crypto.macs.Poly1305
import org.bouncycastle.crypto.params.{KeyParameter, ParametersWithIV}
import org.bouncycastle.util.Pack
import tsec.cipher._
import tsec.cipher.symmetric._
import tsec.common.ManagedRandom
import tsec.keygen.symmetric.SymmetricKeyGen

/** A trait to help factor out the ChaCha20 construction
  * common code.
  *
  * Unfortunately, the covariant bound on C is necessary
  * to define code in terms of `init` and
  * `processBytes`, despite nothing else being used.
  *
  * All ChaCha cipher protocols same the same key size, as well as
  * processing block size, as well as the same authentication
  * tag length since it's dependent on poly.
  *
  */
private[tsec] trait ChaCha20Cipher[A, C <: StreamCipher] {

  /** Note: ChaCha and salsa are stream ciphers but they operate
    * on fixed length blocks of 64 bytes.
    *
    * See:
    * https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_stream/chacha20/ref/chacha20_ref.c
    *
    */
  private val BlockSize = 64
  val KeySize: Int      = 32
  val TagSize: Int      = 16
  def nonceSize: Int

  implicit def defaultKeyGen[F[_]](implicit F: Sync[F]): SymmetricKeyGen[F, A, BouncySecretKey] =
    new SymmetricKeyGen[F, A, BouncySecretKey] with ManagedRandom {
      def generateKey: F[BouncySecretKey[A]] = F.delay {
        val kBytes = new Array[Byte](KeySize)
        nextBytes(kBytes)
        BouncySecretKey(kBytes)
      }

      def build(rawKey: Array[Byte]): F[BouncySecretKey[A]] =
        if (rawKey.length != KeySize)
          F.raiseError(CipherKeyBuildError("Invalid key length"))
        else
          F.pure(BouncySecretKey(rawKey))
    }

  protected def getCipherImpl: C

  /** Mutates the internal
    *
    * @param key
    * @param aad
    * @param in
    */
  protected def poly1305Auth(
      key: KeyParameter,
      aad: AAD,
      in: Array[Byte],
      inSize: Int,
      tagOut: Array[Byte],
      tOutOffset: Int
  ): Unit

  /** Encrypt the plaintext using the chacha function.
    *
    * Run an empty block of 64 bytes through the cipher to
    * generate the Poly1305 key. Encrypt the plaintext,
    * then return the block and the tag concatenated like:
    *
    * cipherText || block
    */
  def unsafeEncrypt(
      plainText: PlainText,
      k: BouncySecretKey[A],
      iv: Iv[A]
  ): CipherText[A] =
    unsafeEncryptAAD(plainText, k, iv, AAD(Array.empty[Byte]))

  /** Encrypt the plaintext using the chacha function.
    *
    * Run an empty block of 64 bytes through the cipher to
    * generate the Poly1305 key. Encrypt the plaintext,
    * then return the block and the tag concatenated like:
    *
    * cipherText || block
    */
  def unsafeEncryptAAD(
      plainText: PlainText,
      k: BouncySecretKey[A],
      iv: Iv[A],
      aad: AAD
  ): CipherText[A] = {
    if (iv.length != nonceSize)
      throw IvError("Invalid Nonce Size")

    val chacha20   = getCipherImpl
    val firstBlock = new Array[Byte](BlockSize)
    val ctOut      = RawCipherText[A](new Array[Byte](plainText.length + TagSize))

    chacha20.init(true, new ParametersWithIV(new KeyParameter(k), iv))
    chacha20.processBytes(firstBlock, 0, firstBlock.length, firstBlock, 0)
    val macKey = new KeyParameter(firstBlock, 0, KeySize)
    util.Arrays.fill(firstBlock, 0.toByte)

    chacha20.processBytes(plainText, 0, plainText.length, ctOut, 0)
    poly1305Auth(macKey, aad, ctOut, plainText.length, ctOut, plainText.length)
    CipherText(ctOut, iv)
  }

  /** Decrypt the plaintext using the chacha function.
    *
    * Using the DJB ciphers, encryption and decryption
    * are the same operation applied. simply in reverse,
    * thus, the `init` parameter in the
    * `StreamCipher` is irrelevant.
    *
    * We assume the ciphertext is of the form
    * cipherText || block
    * Thus, it must have a minimum size of at least one.
    */
  def unsafeDecrypt(
      ct: CipherText[A],
      k: BouncySecretKey[A]
  ): PlainText = unsafeDecryptAAD(ct, k, AAD(Array.empty))

  /** Decrypt the plaintext using the chacha function.
    *
    * Using the DJB ciphers, encryption and decryption
    * are the same operation applied. simply in reverse,
    * thus, the `init` parameter in the
    * `StreamCipher` is irrelevant.
    *
    * We assume the ciphertext is of the form
    * cipherText || block
    * Thus, it must have a minimum size of at least one.
    *
    * Run the empty block on the cipher, run the encryption
    * algorithm (which is essentially decryption) and
    * compare the tag computed from the original ciphertext.
    *
    */
  def unsafeDecryptAAD(
      ct: CipherText[A],
      k: BouncySecretKey[A],
      aad: AAD
  ): PlainText = {
    val ctLen = ct.content.length - TagSize
    if (ctLen < 1)
      throw CipherTextError("Ciphertext is 0 or less bytes")
    if (ct.nonce.length != nonceSize)
      throw IvError("Invalid nonce Size")

    val chacha20    = getCipherImpl
    val firstBlock  = new Array[Byte](BlockSize)
    val out         = PlainText(new Array[Byte](ctLen))
    val computedTag = new Array[Byte](TagSize)
    val oldTag      = new Array[Byte](TagSize)
    System.arraycopy(ct.content, ctLen, oldTag, 0, TagSize)

    chacha20.init(false, new ParametersWithIV(new KeyParameter(k), ct.nonce))
    chacha20.processBytes(firstBlock, 0, firstBlock.length, firstBlock, 0)
    val macKey = new KeyParameter(firstBlock, 0, KeySize)
    util.Arrays.fill(firstBlock, 0.toByte)
    chacha20.processBytes(ct.content, 0, ctLen, out, 0)
    poly1305Auth(macKey, aad, ct.content, ctLen, computedTag, 0)

    if (!MessageDigest.isEqual(computedTag, oldTag))
      throw AuthTagError("Tags do not match")

    PlainText(out)
  }

  /** Encrypt the plaintext using the chacha function.
    *
    * Run an empty block of 64 bytes through the cipher to
    * generate the Poly1305 key. Encrypt the plaintext,
    * then return the block and the tag in a separate fashion.
    */
  def unsafeEncryptDetached(
      plainText: PlainText,
      k: BouncySecretKey[A],
      iv: Iv[A]
  ): (CipherText[A], AuthTag[A]) =
    unsafeEncryptDetachedAAD(plainText, k, iv, AAD(Array.empty[Byte]))

  /** Encrypt the plaintext using the chacha function.
    *
    * Run an empty block of 64 bytes through the cipher to
    * generate the Poly1305 key. Encrypt the plaintext,
    * then return the block and the tag in a separate fashion.
    */
  def unsafeEncryptDetachedAAD(
      plainText: PlainText,
      k: BouncySecretKey[A],
      iv: Iv[A],
      aad: AAD
  ): (CipherText[A], AuthTag[A]) = {
    if (iv.length != nonceSize)
      throw IvError("Invalid nonce size")

    val chacha20   = getCipherImpl
    val ctOut      = RawCipherText[A](new Array[Byte](plainText.length))
    val tagOut     = AuthTag[A](new Array[Byte](TagSize))
    val firstBlock = new Array[Byte](BlockSize)

    chacha20.init(true, new ParametersWithIV(new KeyParameter(k), iv))
    chacha20.processBytes(firstBlock, 0, firstBlock.length, firstBlock, 0)
    val macKey = new KeyParameter(firstBlock, 0, KeySize)
    util.Arrays.fill(firstBlock, 0.toByte)
    chacha20.processBytes(plainText, 0, plainText.length, ctOut, 0)
    poly1305Auth(macKey, aad, ctOut, plainText.length, tagOut, 0)
    (CipherText(ctOut, iv), tagOut)
  }

  /** Decrypt the plaintext using the chacha function.
    *
    * Run an empty block of 64 bytes through the cipher to
    * generate the Poly1305 key. Decrypt the plaintext,
    * generate the authentication tag and compare it to the
    * supplied tag.
    *
    */
  def unsafeDecryptDetached(
      ct: CipherText[A],
      authTag: AuthTag[A],
      k: BouncySecretKey[A]
  ): PlainText = unsafeDecryptDetachedAAD(ct, authTag, k, AAD(Array.empty[Byte]))

  def unsafeDecryptDetachedAAD(
      ct: CipherText[A],
      authTag: AuthTag[A],
      k: BouncySecretKey[A],
      aad: AAD
  ): PlainText = {
    if (ct.content.length < 1)
      throw CipherTextError("Ciphertext is 0 or less bytes")
    if (ct.nonce.length != nonceSize)
      throw IvError("Invalid nonce Size")

    val cipher      = getCipherImpl
    val firstBlock  = new Array[Byte](BlockSize)
    val out         = PlainText(new Array[Byte](ct.content.length))
    val computedTag = new Array[Byte](TagSize)

    cipher.init(false, new ParametersWithIV(new KeyParameter(k), ct.nonce))
    cipher.processBytes(firstBlock, 0, firstBlock.length, firstBlock, 0)
    val macKey = new KeyParameter(firstBlock, 0, KeySize)
    util.Arrays.fill(firstBlock, 0.toByte)

    cipher.processBytes(ct.content, 0, ct.content.length, out, 0)
    poly1305Auth(macKey, aad, ct.content, ct.content.length, computedTag, 0)

    if (!MessageDigest.isEqual(computedTag, authTag))
      throw AuthTagError("Tags do not match")

    PlainText(out)
  }

  implicit def authEncryptor[F[_]](implicit F: Sync[F]): AADEncryptor[F, A, BouncySecretKey] =
    new AADEncryptor[F, A, BouncySecretKey] {
      def encryptWithAAD(
          plainText: PlainText,
          key: BouncySecretKey[A],
          iv: Iv[A],
          aad: AAD
      ): F[CipherText[A]] =
        F.delay(unsafeEncryptAAD(plainText, key, iv, aad))

      def encryptWithAADDetached(
          plainText: PlainText,
          key: BouncySecretKey[A],
          iv: Iv[A],
          aad: AAD
      ): F[(CipherText[A], AuthTag[A])] =
        F.delay(unsafeEncryptDetachedAAD(plainText, key, iv, aad))

      def decryptWithAAD(
          cipherText: CipherText[A],
          key: BouncySecretKey[A],
          aad: AAD
      ): F[PlainText] =
        F.delay(unsafeDecryptAAD(cipherText, key, aad))

      def decryptWithAADDetached(
          cipherText: CipherText[A],
          key: BouncySecretKey[A],
          aad: AAD,
          authTag: AuthTag[A]
      ): F[PlainText] =
        F.delay(unsafeDecryptDetachedAAD(cipherText, authTag, key, aad))

      def encryptDetached(
          plainText: PlainText,
          key: BouncySecretKey[A],
          iv: Iv[A]
      ): F[(CipherText[A], AuthTag[A])] =
        F.delay(unsafeEncryptDetached(plainText, key, iv))

      def decryptDetached(
          cipherText: CipherText[A],
          key: BouncySecretKey[A],
          authTag: AuthTag[A]
      ): F[PlainText] =
        F.delay(unsafeDecryptDetached(cipherText, authTag, key))

      def encrypt(
          plainText: PlainText,
          key: BouncySecretKey[A],
          iv: Iv[A]
      ): F[CipherText[A]] =
        F.delay(unsafeEncrypt(plainText, key, iv))

      def decrypt(cipherText: CipherText[A], key: BouncySecretKey[A]): F[PlainText] =
        F.delay(unsafeDecrypt(cipherText, key))
    }

  def defaultIvGen[F[_]](implicit F: Sync[F]): IvGen[F, A] =
    new IvGen[F, A] with ManagedRandom {

      def genIv: F[Iv[A]] =
        F.delay(genIvUnsafe)

      def genIvUnsafe: Iv[A] = {
        val nonce = new Array[Byte](nonceSize)
        nextBytes(nonce)
        Iv[A](nonce)
      }
    }
}

private[tsec] trait IETFChaCha20Cipher[A, C <: StreamCipher] extends ChaCha20Cipher[A, C] {
  private val BytePadding = new Array[Byte](16)

  protected def poly1305Auth(
      key: KeyParameter,
      aad: AAD,
      in: Array[Byte],
      inSize: Int,
      tagOut: Array[Byte],
      tOutOffset: Int
  ): Unit = {
    val poly1305 = new Poly1305()
    val ctLen    = Pack.longToLittleEndian(inSize & 0xFFFFFFFFL)
    val aadLen   = Pack.longToLittleEndian(aad.length & 0xFFFFFFFFL)

    poly1305.init(key)
    poly1305.update(aad, 0, aad.length)
    poly1305.update(BytePadding, 0, (0x10 - aad.length) & 0xF)
    poly1305.update(in, 0, inSize)
    poly1305.update(BytePadding, 0, (0x10 - inSize) & 0xF)
    poly1305.update(aadLen, 0, ctLen.length)
    poly1305.update(ctLen, 0, ctLen.length)
    poly1305.doFinal(tagOut, tOutOffset)
  }
}
