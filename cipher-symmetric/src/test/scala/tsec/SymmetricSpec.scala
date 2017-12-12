package tsec

import org.scalatest.MustMatchers
import org.scalatest.prop.PropertyChecks
import tsec.common._
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.mode._
import tsec.cipher.common.padding._
import tsec.cipher.symmetric.imports._
import tsec.cipher.symmetric.imports.aead._
import scala.util.Random

class SymmetricSpec extends TestSpec with MustMatchers with PropertyChecks {

  def cipherTest[A, M, P](
      implicit symm: SymmetricCipher[A],
      mode: CipherMode[M],
      p: Padding[P],
      keyGen: CipherKeyGen[A]
  ): Unit = {

    val spec = s"""${symm.algorithm}_${keyGen.keyLength}/${mode.algorithm}/${p.algorithm}"""

    behavior of spec

    it should "Encrypt and decrypt for the same key" in {
      forAll { (testMessage: String) =>
        val testPlainText = PlainText(testMessage.utf8Bytes)
        val testEncryptionDecryption: Either[CipherError, String] = for {
          key       <- keyGen.generateKey()
          instance  <- JCASymmCipherImpure[A, M, P]
          encrypted <- instance.encrypt(testPlainText, key)
          decrypted <- instance.decrypt(encrypted, key)
        } yield decrypted.content.toUtf8String
        testEncryptionDecryption must equal(Right(testMessage))
      }
    }

    it should "Be able to build a correct key from a repr" in {
      forAll { (testMessage: String) =>
        val testPlainText = PlainText(testMessage.utf8Bytes)
        val testEncryptionDecryption: Either[CipherError, String] = for {
          key       <- keyGen.generateKey()
          instance  <- JCASymmCipherImpure[A, M, P]
          encrypted <- instance.encrypt(testPlainText, key)
          keyRepr = key.getEncoded
          built     <- keyGen.buildKey(keyRepr)
          decrypted <- instance.decrypt(encrypted, built)
        } yield decrypted.content.toUtf8String
        testEncryptionDecryption must equal(Right(testMessage))
      }
    }

    it should "not decrypt properly for an incorrect key" in {
      forAll { (testMessage: String) =>
        val testPlainText = PlainText(testMessage.utf8Bytes)
        val testEncryptionDecryption: Either[CipherError, String] = for {
          key1      <- keyGen.generateKey()
          key2      <- keyGen.generateKey()
          instance  <- JCASymmCipherImpure[A, M, P]
          encrypted <- instance.encrypt(testPlainText, key1)
          decrypted <- instance.decrypt(encrypted, key2)
        } yield new String(decrypted.content, "UTF-8")
        if (!testMessage.isEmpty)
          testEncryptionDecryption mustNot equal(Right(testMessage))
      }
    }

    behavior of (spec + " Key Generator")

    it should "Not allow a key with incorrect length" in {
      val randomKey: Array[Byte] = (1 until 100).toArray.map(_ => Random.nextInt(128).toByte)
      val keyLenTest: Either[CipherKeyBuildError, Boolean] = for {
        k <- keyGen.buildKey(randomKey)
      } yield k.getEncoded.length < randomKey.length

      keyLenTest mustBe a[Left[_, _]]
    }
  }

  def authCipherTest[A, M, P](
      implicit symm: AEADCipher[A],
      mode: AEADMode[M],
      p: Padding[P],
      keyGen: CipherKeyGen[A]
  ): Unit = {

    val spec = s"""${symm.algorithm}_${keyGen.keyLength}/${mode.algorithm}/${p.algorithm}"""

    behavior of spec

    it should "Encrypt and decrypt for the same key" in {
      forAll { (testMessage: String) =>
        val testPlainText = PlainText(testMessage.utf8Bytes)
        val testEncryptionDecryption: Either[CipherError, String] = for {
          key       <- keyGen.generateKey()
          instance  <- JCAAEADImpure[A, M, P]
          encrypted <- instance.encrypt(testPlainText, key)
          decrypted <- instance.decrypt(encrypted, key)
        } yield decrypted.content.toUtf8String
        testEncryptionDecryption must equal(Right(testMessage))
      }
    }

    it should "Be able to build a correct key from a repr" in {
      forAll { (testMessage: String) =>
        val testPlainText = PlainText(testMessage.utf8Bytes)
        val testEncryptionDecryption: Either[CipherError, String] = for {
          key       <- keyGen.generateKey()
          instance  <- JCAAEADImpure[A, M, P]
          encrypted <- instance.encrypt(testPlainText, key)
          keyRepr = key.getEncoded
          built     <- keyGen.buildKey(keyRepr)
          decrypted <- instance.decrypt(encrypted, built)
        } yield decrypted.content.toUtf8String
        testEncryptionDecryption must equal(Right(testMessage))
      }
    }

    it should "Encrypt and decrypt for the same key and AEAD" in {
      forAll { (testMessage: String, aadData: String) =>
        val testPlainText = PlainText(testMessage.utf8Bytes)
        val aad           = AAD(aadData.utf8Bytes)
        val testEncryptionDecryption: Either[CipherError, String] = for {
          key       <- keyGen.generateKey()
          instance  <- JCAAEADImpure[A, M, P]
          encrypted <- instance.encryptAAD(testPlainText, key, aad)
          decrypted <- instance.decryptAAD(encrypted, key, aad)
        } yield decrypted.content.toUtf8String
        testEncryptionDecryption must equal(Right(testMessage))
      }
    }

    it should "not decrypt properly for an incorrect key" in {
      forAll { (testMessage: String) =>
        val testPlainText = PlainText(testMessage.utf8Bytes)
        val testEncryptionDecryption: Either[CipherError, String] = for {
          key1      <- keyGen.generateKey()
          key2      <- keyGen.generateKey()
          instance  <- JCAAEADImpure[A, M, P]
          encrypted <- instance.encrypt(testPlainText, key1)
          decrypted <- instance.decrypt(encrypted, key2)
        } yield new String(decrypted.content, "UTF-8")
        if (!testMessage.isEmpty)
          testEncryptionDecryption mustNot equal(Right(testMessage))
      }
    }

    it should "not decrypt properly for correct key but incorrect AAD" in {
      forAll { (testMessage: String, AAD1: String, AAD2: String) =>
        val testPlainText = PlainText(testMessage.utf8Bytes)
        val aad1          = AAD(AAD1.utf8Bytes)
        val aad2          = AAD(AAD2.utf8Bytes)
        val testEncryptionDecryption: Either[CipherError, String] = for {
          key1      <- keyGen.generateKey()
          instance  <- JCAAEADImpure[A, M, P]
          encrypted <- instance.encryptAAD(testPlainText, key1, aad1)
          decrypted <- instance.decryptAAD(encrypted, key1, aad2)
        } yield new String(decrypted.content, "UTF-8")
        if (!testMessage.isEmpty && !AAD1.isEmpty && !AAD2.isEmpty)
          testEncryptionDecryption mustNot equal(Right(testMessage))
      }
    }

    behavior of (spec + " Key Generator")

    it should "Not allow a key with incorrect length" in {
      val randomKey: Array[Byte] = (1 until 100).toArray.map(_ => Random.nextInt(128).toByte)
      val keyLenTest: Either[CipherKeyBuildError, Boolean] = for {
        k <- keyGen.buildKey(randomKey)
      } yield k.getEncoded.length < randomKey.length

      keyLenTest mustBe a[Left[_, _]]
    }
  }

}
