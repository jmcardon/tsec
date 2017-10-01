package tsec

import org.scalatest.MustMatchers
import tsec.cipher.common._
import tsec.cipher.common.mode.ModeKeySpec
import tsec.cipher.symmetric.instances.{JCASymmetricCipher, SecretKey, SymmetricAlgorithm}
import tsec.core.JKeyGenerator
import scala.annotation.tailrec
import tsec.core.ByteUtils._
import scala.util.Random

class SymmetricSpec extends TestSpec with MustMatchers{

  def utf8String(array: Array[Byte]) = new String(array, "UTF-8")

  def arrayCompare(array1: Array[Byte], array2: Array[Byte]): Boolean =
    if (array1.length != array2.length)
      false
    else
      (array1 zip array2).forall(r => r._1 == r._2)

  def cipherTest[A, M, P](
    implicit symm: SymmetricAlgorithm[A],
    mode: ModeKeySpec[M],
    p: Padding[P],
    keyGen: JKeyGenerator[A, SecretKey, CipherKeyBuildError]
  ): Unit = {
    val testMessage                       = "The Moose is Loose"
    val testPlainText: PlainText = PlainText(testMessage.getBytes("UTF-8"))

    val spec = s"""${symm.algorithm}_${symm.keyLength}/${mode.algorithm}/${p.algorithm}"""

    behavior of spec

    it should "Encrypt and decrypt for the same key" in {
      val testEncryptionDecryption: Either[CipherError, String] = for {
        key       <- keyGen.generateKey()
        instance  <- JCASymmetricCipher[A, M, P]
        encrypted <- instance.encrypt(testPlainText, key)
        decrypted <- instance.decrypt(encrypted, key)
      } yield utf8String(decrypted.content)
      testEncryptionDecryption must equal(Right(testMessage))
    }

    /*
    We will test only a few thousand, but part of the point is simply to test proper implementation of secureRandom
     */
    it should "Not reuse IVs" in {

      @tailrec def tailrecGenIVs(
        last: CipherText[A, M, P],
        counter: Int,
        instance: JCASymmetricCipher[A, M, P],
        key: SecretKey[A]
      ): Boolean =
        if (counter > 0) {
          instance.encrypt(testPlainText, key) match {
            case Right(r) =>
              if (!arrayCompare(last.iv, r.iv))
                tailrecGenIVs(r, counter - 1, instance, key)
              else
                false
            case Left(_) =>
              false
          }
        } else true

      val testIvs: Either[CipherError, Boolean] = for {
        key      <- keyGen.generateKey()
        instance <- JCASymmetricCipher[A, M, P]
        first    <- instance.encrypt(testPlainText, key)
      } yield tailrecGenIVs(first, 100000, instance, key)

      testIvs mustBe Right(true)
    }

    it should "not decrypt properly for an incorrect key" in {
      val testEncryptionDecryption: Either[CipherError, String] = for {
        key1      <- keyGen.generateKey()
        key2      <- keyGen.generateKey()
        instance  <- JCASymmetricCipher[A, M, P]
        encrypted <- instance.encrypt(testPlainText, key1)
        decrypted <- instance.decrypt(encrypted, key2)
      } yield new String(decrypted.content, "UTF-8")
      testEncryptionDecryption mustNot equal(Right(testMessage))
    }

    behavior of (spec + " Key Generator")

    it should "Not allow a key with incorrect length" in {
      val randomKey: Array[Byte] = (1 until 100).toArray.map(_ => Random.nextInt(128).toByte)
      val keyLenTest: Either[CipherKeyBuildError, Boolean] = for {
        k <- keyGen.buildKey(randomKey)
      } yield k.key.getEncoded.length < randomKey.length

      keyLenTest mustBe a[Left[_, _]]
    }
  }

  def authCipherTest[A, M, P](
    implicit symm: SymmetricAlgorithm[A],
    mode: ModeKeySpec[M],
    p: Padding[P],
    keyGen: JKeyGenerator[A, SecretKey, CipherKeyBuildError]
  ): Unit = {
    val testMessage                       = "The Moose is Loose"
    val testPlainText: PlainText = PlainText(testMessage.getBytes("UTF-8"))

    val spec = s"""${symm.algorithm}_${symm.keyLength}/${mode.algorithm}/${p.algorithm}"""

    behavior of spec

    it should "Encrypt and decrypt for the same key" in {
      val testEncryptionDecryption: Either[CipherError, String] = for {
        key       <- keyGen.generateKey()
        instance  <- JCASymmetricCipher[A, M, P]
        encrypted <- instance.encrypt(testPlainText, key)
        decrypted <- instance.decrypt(encrypted, key)
      } yield utf8String(decrypted.content)
      testEncryptionDecryption must equal(Right(testMessage))
    }

    it should "Encrypt and decrypt for the same key and AEAD" in {
      val aad = AAD("HI HELLO!".utf8Bytes)
      val testEncryptionDecryption: Either[CipherError, String] = for {
        key       <- keyGen.generateKey()
        instance  <- JCASymmetricCipher[A, M, P]
        encrypted <- instance.encryptAAD(testPlainText, key, aad)
        decrypted <- instance.decryptAAD(encrypted, key, aad)
      } yield utf8String(decrypted.content)
      testEncryptionDecryption must equal(Right(testMessage))
    }

    /*
    We will test only a few thousand, but part of the point is simply to test proper implementation of secureRandom
     */
    it should "Not reuse IVs" in {

      @tailrec def tailrecGenIVs(
        last: CipherText[A, M, P],
        counter: Int,
        instance: JCASymmetricCipher[A, M, P],
        key: SecretKey[A]
      ): Boolean =
        if (counter > 0) {
          instance.encrypt(testPlainText, key) match {
            case Right(r) =>
              if (!arrayCompare(last.iv, r.iv))
                tailrecGenIVs(r, counter - 1, instance, key)
              else
                false
            case Left(_) =>
              false
          }
        } else true

      val testIvs: Either[CipherError, Boolean] = for {
        key      <- keyGen.generateKey()
        instance <- JCASymmetricCipher[A, M, P]
        first    <- instance.encrypt(testPlainText, key)
      } yield tailrecGenIVs(first, 100000, instance, key)

      testIvs mustBe Right(true)
    }

    it should "not decrypt properly for an incorrect key" in {
      val testEncryptionDecryption: Either[CipherError, String] = for {
        key1      <- keyGen.generateKey()
        key2      <- keyGen.generateKey()
        instance  <- JCASymmetricCipher[A, M, P]
        encrypted <- instance.encrypt(testPlainText, key1)
        decrypted <- instance.decrypt(encrypted, key2)
      } yield new String(decrypted.content, "UTF-8")
      testEncryptionDecryption mustNot equal(Right(testMessage))
    }

    it should "not decrypt properly for correct key but incorrect AAD" in {
      val aad1 = AAD("HI HELLO!".utf8Bytes)
      val aad2 = AAD("HI HELLO2!".utf8Bytes)
      val testEncryptionDecryption: Either[CipherError, String] = for {
        key1      <- keyGen.generateKey()
        instance  <- JCASymmetricCipher[A, M, P]
        encrypted <- instance.encryptAAD(testPlainText, key1, aad1)
        decrypted <- instance.decryptAAD(encrypted, key1, aad2)
      } yield new String(decrypted.content, "UTF-8")
      testEncryptionDecryption mustNot equal(Right(testMessage))
    }

    behavior of (spec + " Key Generator")

    it should "Not allow a key with incorrect length" in {
      val randomKey: Array[Byte] = (1 until 100).toArray.map(_ => Random.nextInt(128).toByte)
      val keyLenTest: Either[CipherKeyBuildError, Boolean] = for {
        k <- keyGen.buildKey(randomKey)
      } yield k.key.getEncoded.length < randomKey.length

      keyLenTest mustBe a[Left[_, _]]
    }
  }

}
