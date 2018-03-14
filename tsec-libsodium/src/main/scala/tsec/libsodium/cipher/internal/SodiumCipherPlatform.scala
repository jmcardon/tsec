package tsec.libsodium.cipher.internal

import cats.Id
import cats.effect.Sync
import tsec.cipher.symmetric.{AuthEncryptor, IvGen, _}
import tsec.keygen.symmetric.{IdKeyGen, SymmetricKeyGen}
import tsec.libsodium.ScalaSodium
import tsec.libsodium.cipher.SodiumCipherError._
import tsec.libsodium.cipher._

private[tsec] trait SodiumCipherPlatform[A]
    extends SodiumKeyGenerator[A]
    with SodiumAuthCipher[A]
    with SodiumCipherAPI[A] {
  implicit val authCipher: SodiumAuthCipher[A] = this

  def defaultIvGen[F[_]](implicit F: Sync[F], S: ScalaSodium): IvGen[F, A] = new IvGen[F, A] {
    def genIv: F[Iv[A]] = F.delay {
      val nonce = Iv[A](new Array[Byte](nonceLen))
      S.randombytes_buf(nonce, nonceLen)
      nonce
    }

    def genIvUnsafe: Iv[A] = {
      val nonce = Iv[A](new Array[Byte](nonceLen))
      S.randombytes_buf(nonce, nonceLen)
      nonce
    }
  }

  implicit def genKeyF[F[_]](implicit F: Sync[F], S: ScalaSodium): SymmetricKeyGen[F, A, SodiumKey] =
    new SymmetricKeyGen[F, A, SodiumKey] {
      def generateKey: F[SodiumKey[A]] =
        F.delay(impl.generateKeyUnsafe)

      def build(rawKey: Array[Byte]): F[SodiumKey[A]] = F.delay(impl.buildKeyUnsafe(rawKey))
    }

  implicit def unsafeKeyGen(implicit S: ScalaSodium): IdKeyGen[A, SodiumKey] =
    new IdKeyGen[A, SodiumKey] {
      def generateKey: Id[SodiumKey[A]] = impl.generateKeyUnsafe

      def build(rawKey: Array[Byte]): Id[SodiumKey[A]] = impl.buildKeyUnsafe(rawKey)
    }

  implicit def genEncryptor[F[_]](implicit F: Sync[F], S: ScalaSodium): AuthEncryptor[F, A, SodiumKey] =
    new AuthEncryptor[F, A, SodiumKey] {
      def encrypt(plainText: PlainText, key: SodiumKey[A], iv: Iv[A]): F[CipherText[A]] =
        F.delay(impl.unsafeEncrypt(plainText, key, iv))

      def decrypt(cipherText: CipherText[A], key: SodiumKey[A]): F[PlainText] =
        F.delay(impl.unsafeDecrypt(cipherText, key))

      def encryptDetached(plainText: PlainText, key: SodiumKey[A], iv: Iv[A]): F[(CipherText[A], AuthTag[A])] =
        F.delay(impl.unsafeEncryptDetached(plainText, key, iv))

      def decryptDetached(cipherText: CipherText[A], key: SodiumKey[A], authTag: AuthTag[A]): F[PlainText] =
        F.delay(impl.unsafeDecryptDetached(cipherText, key, authTag))
    }

  object impl {

    final def generateKeyUnsafe(implicit s: ScalaSodium): SodiumKey[A] = {
      val bytes = new Array[Byte](keyLength)
      s.randombytes_buf(bytes, keyLength)
      SodiumKey[A](bytes)
    }

    final def buildKeyUnsafe(key: Array[Byte])(implicit s: ScalaSodium): SodiumKey[A] =
      if (key.length != keyLength)
        throw CipherKeyError("Invalid key length")
      else
        SodiumKey[A](key)

    final def unsafeEncrypt(plainText: PlainText, key: SodiumKey[A], nonce: Iv[A])(
        implicit S: ScalaSodium
    ): CipherText[A] = {
      val outArray = RawCipherText[A](new Array[Byte](plainText.length + macLen))
      if (sodiumEncrypt(outArray, plainText, nonce, key) != 0)
        throw EncryptError("Invalid encryption Info")

      CipherText[A](outArray, nonce)
    }

    final def unsafeDecrypt(cipherText: CipherText[A], key: SodiumKey[A])(
        implicit S: ScalaSodium
    ): PlainText = {
      val originalMessage = new Array[Byte](cipherText.content.length - macLen)
      if (sodiumDecrypt(originalMessage, cipherText, key) != 0)
        throw DecryptError("Invalid Decryption info")
      PlainText(originalMessage)
    }

    final def unsafeEncryptDetached(plainText: PlainText, key: SodiumKey[A], nonce: Iv[A])(
        implicit S: ScalaSodium
    ): (CipherText[A], AuthTag[A]) = {
      val outArray = RawCipherText[A](new Array[Byte](plainText.length))
      val macOut   = new Array[Byte](macLen)
      if (sodiumEncryptDetached(outArray, macOut, plainText, nonce, key) != 0)
        throw EncryptError("Invalid encryption Info")

      (CipherText[A](outArray, nonce), AuthTag[A](macOut))
    }

    final def unsafeDecryptDetached(cipherText: CipherText[A], key: SodiumKey[A], authTag: AuthTag[A])(
        implicit S: ScalaSodium
    ): PlainText = {
      val originalMessage = new Array[Byte](cipherText.content.length)
      if (sodiumDecryptDetached(originalMessage, cipherText, authTag, key) != 0)
        throw DecryptError("Invalid Decryption info")
      PlainText(originalMessage)
    }
  }
}
