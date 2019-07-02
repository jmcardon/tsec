package tsec

import cats.effect.IO
import org.scalacheck._
import tsec.cipher.symmetric.{Encryptor, IvGen, _}
import tsec.common._
import tsec.keygen.symmetric._

import scala.util.Random

class SymmetricSpec extends TestSpec {

  final def cipherTest[A, K[_]](testName: String, gen: IvGen[IO, A])(
      implicit E: Encryptor[IO, A, K],
      S: SymmetricKeyGen[IO, A, K]
  ): Unit = {

    val spec = s"""Cipher test: $testName"""

    behavior of spec

    implicit val defaultStrat: IvGen[IO, A] = gen

    it should "Encrypt and decrypt for the same key" in {
      forAll { (testMessage: String) =>
        val testPlainText = PlainText(testMessage.utf8Bytes)
        val testEncryptionDecryption: IO[String] = for {
          key       <- S.generateKey
          encrypted <- E.encrypt(testPlainText, key)
          decrypted <- E.decrypt(encrypted, key)
        } yield decrypted.toUtf8String
        testEncryptionDecryption.attempt.unsafeRunSync() must equal(Right(testMessage))
      }
    }

    it should "not decrypt properly for an incorrect key" in {
      forAll { (testMessage: String) =>
        val testPlainText = PlainText(testMessage.utf8Bytes)
        val testEncryptionDecryption: IO[String] = for {
          key1      <- S.generateKey
          key2      <- S.generateKey
          encrypted <- E.encrypt(testPlainText, key1)
          decrypted <- E.decrypt(encrypted, key2)
        } yield decrypted.toUtf8String
        if (!testMessage.isEmpty)
          testEncryptionDecryption.attempt.unsafeRunSync() mustNot equal(Right(testMessage))
      }
    }

    behavior of (spec + " Key Generator")

    it should "Not allow a key with incorrect length" in {
      //Totally ok, since no keys are 100 in size
      val randomKey: Array[Byte] = (1 until 100).toArray.map(_ => Random.nextInt(128).toByte)
      val keyLenTest: IO[K[A]] = for {
        k <- S.build(randomKey)
      } yield k

      keyLenTest.attempt.unsafeRunSync() mustBe a[Left[_, _]]
    }
  }

  final def authCipherTest[A, K[_]](testName: String, gen: IvGen[IO, A])(
      implicit E: AuthEncryptor[IO, A, K],
      S: SymmetricKeyGen[IO, A, K]
  ): Unit = {

    val spec = s"""Cipher test: $testName"""

    behavior of spec

    implicit val defaultStrat: IvGen[IO, A] = gen

    it should "Encrypt and decrypt for the same key" in {
      forAll { (testMessage: String) =>
        val testPlainText = PlainText(testMessage.utf8Bytes)
        val testEncryptionDecryption: IO[String] = for {
          key       <- S.generateKey
          encrypted <- E.encrypt(testPlainText, key)
          decrypted <- E.decrypt(encrypted, key)
        } yield decrypted.toUtf8String
        if (!testMessage.isEmpty)
          testEncryptionDecryption.attempt.unsafeRunSync() must equal(Right(testMessage))
      }
    }

    it should "not decrypt properly for an incorrect key" in {
      forAll { (testMessage: String) =>
        val testPlainText = PlainText(testMessage.utf8Bytes)
        val testEncryptionDecryption: IO[String] = for {
          key1      <- S.generateKey
          key2      <- S.generateKey
          encrypted <- E.encrypt(testPlainText, key1)
          decrypted <- E.decrypt(encrypted, key2)
        } yield decrypted.toUtf8String
        if (!testMessage.isEmpty)
          testEncryptionDecryption.attempt.unsafeRunSync() mustNot equal(Right(testMessage))
      }
    }

    /** Detached mode tests **/
    it should "Encrypt and decrypt for the same key in detached mode" in {
      forAll { (testMessage: String) =>
        val testPlainText = PlainText(testMessage.utf8Bytes)
        val testEncryptionDecryption: IO[String] = for {
          key       <- S.generateKey
          encrypted <- E.encryptDetached(testPlainText, key)
          decrypted <- E.decryptDetached(encrypted._1, key, encrypted._2)
        } yield decrypted.toUtf8String
        if (!testMessage.isEmpty)
          testEncryptionDecryption.attempt.unsafeRunSync() must equal(Right(testMessage))
      }
    }

    it should "not decrypt properly for an incorrect key in detached mode" in {
      forAll { (testMessage: String) =>
        val testPlainText = PlainText(testMessage.utf8Bytes)
        val testEncryptionDecryption: IO[String] = for {
          key1      <- S.generateKey
          key2      <- S.generateKey
          encrypted <- E.encryptDetached(testPlainText, key1)
          decrypted <- E.decryptDetached(encrypted._1, key2, encrypted._2)
        } yield decrypted.toUtf8String
        if (!testMessage.isEmpty)
          testEncryptionDecryption.attempt.unsafeRunSync() mustNot equal(Right(testMessage))
      }
    }

    behavior of (spec + " Key Generator")

    it should "Not allow a key with incorrect length" in {
      //Totally ok, since no keys are 100 in size
      val randomKey: Array[Byte] = (1 until 100).toArray.map(_ => Random.nextInt(128).toByte)
      val keyLenTest: IO[K[A]] = for {
        k <- S.build(randomKey)
      } yield k

      keyLenTest.attempt.unsafeRunSync() mustBe a[Left[_, _]]
    }
  }

  final def aeadCipherTest[A, K[_]](testName: String, gen: IvGen[IO, A])(
      implicit E: AADEncryptor[IO, A, K],
      S: SymmetricKeyGen[IO, A, K]
  ): Unit = {
    implicit val strat = gen

    val spec = s"""AEAD Cipher: $testName"""

    behavior of spec

    it should "Encrypt and decrypt for the same key" in {
      forAll { (testMessage: String) =>
        val testPlainText = PlainText(testMessage.utf8Bytes)
        val testEncryptionDecryption: IO[String] = for {
          key       <- S.generateKey
          encrypted <- E.encrypt(testPlainText, key)
          decrypted <- E.decrypt(encrypted, key)
        } yield decrypted.toUtf8String
        if (!testMessage.isEmpty)
          testEncryptionDecryption.attempt.unsafeRunSync() must equal(Right(testMessage))
      }
    }

    it should "Encrypt and decrypt for the same key and AEAD" in {
      forAll { (testMessage: String, aadData: String) =>
        val testPlainText = PlainText(testMessage.utf8Bytes)
        val aad           = AAD(aadData.utf8Bytes)
        val testEncryptionDecryption: IO[String] = for {
          key       <- S.generateKey
          encrypted <- E.encryptWithAAD(testPlainText, key, aad)
          decrypted <- E.decryptWithAAD(encrypted, key, aad)
        } yield decrypted.toUtf8String
        if (!testMessage.isEmpty)
          testEncryptionDecryption.attempt.unsafeRunSync() must equal(Right(testMessage))
      }
    }

    it should "not decrypt properly for an incorrect key" in {
      forAll { (testMessage: String) =>
        val testPlainText = PlainText(testMessage.utf8Bytes)
        val testEncryptionDecryption: IO[String] = for {
          key1      <- S.generateKey
          key2      <- S.generateKey
          encrypted <- E.encrypt(testPlainText, key1)
          decrypted <- E.decrypt(encrypted, key2)
        } yield decrypted.toUtf8String
        if (!testMessage.isEmpty)
          testEncryptionDecryption.attempt.unsafeRunSync() mustNot equal(Right(testMessage))
      }
    }

    it should "not decrypt properly for correct key but incorrect AAD" in {
      forAll { (testMessage: String, AAD1: String, AAD2: String) =>
        val testPlainText = PlainText(testMessage.utf8Bytes)
        val aad1          = AAD(AAD1.utf8Bytes)
        val aad2          = AAD(AAD2.utf8Bytes)
        val testEncryptionDecryption: IO[String] = for {
          key1      <- S.generateKey
          encrypted <- E.encryptWithAAD(testPlainText, key1, aad1)
          decrypted <- E.decryptWithAAD(encrypted, key1, aad2)
        } yield decrypted.toUtf8String
        if (!testMessage.isEmpty && !AAD1.isEmpty && !AAD2.isEmpty)
          testEncryptionDecryption.attempt.unsafeRunSync() mustNot equal(Right(testMessage))
      }
    }

    /** Detached mode tests **/
    it should "Encrypt and decrypt for the same key in detached mode" in {
      forAll { (testMessage: String) =>
        val testPlainText = PlainText(testMessage.utf8Bytes)
        val testEncryptionDecryption: IO[String] = for {
          key       <- S.generateKey
          encrypted <- E.encryptDetached(testPlainText, key)
          decrypted <- E.decryptDetached(encrypted._1, key, encrypted._2)
        } yield decrypted.toUtf8String
        if (!testMessage.isEmpty)
          testEncryptionDecryption.attempt.unsafeRunSync() must equal(Right(testMessage))
      }
    }

    it should "Encrypt and decrypt for the same key and AEAD in detached mode" in {
      forAll { (testMessage: String, aadData: String) =>
        val testPlainText = PlainText(testMessage.utf8Bytes)
        val aad           = AAD(aadData.utf8Bytes)
        val testEncryptionDecryption: IO[String] = for {
          key       <- S.generateKey
          encrypted <- E.encryptWithAADDetached(testPlainText, key, aad)
          decrypted <- E.decryptWithAADDetached(encrypted._1, key, aad, encrypted._2)
        } yield decrypted.toUtf8String
        if (!testMessage.isEmpty)
          testEncryptionDecryption.attempt.unsafeRunSync() must equal(Right(testMessage))
      }
    }

    it should "not decrypt properly for an incorrect key in detached mode" in {
      forAll { (testMessage: String) =>
        val testPlainText = PlainText(testMessage.utf8Bytes)
        val testEncryptionDecryption: IO[String] = for {
          key1      <- S.generateKey
          key2      <- S.generateKey
          encrypted <- E.encryptDetached(testPlainText, key1)
          decrypted <- E.decryptDetached(encrypted._1, key2, encrypted._2)
        } yield decrypted.toUtf8String
        if (!testMessage.isEmpty)
          testEncryptionDecryption.attempt.unsafeRunSync() mustNot equal(Right(testMessage))
      }
    }

    it should "not decrypt properly for correct key but incorrect AAD in detached mode" in {
      forAll { (testMessage: String, AAD1: String, AAD2: String) =>
        val testPlainText = PlainText(testMessage.utf8Bytes)
        val aad1          = AAD(AAD1.utf8Bytes)
        val aad2          = AAD(AAD2.utf8Bytes)
        val testEncryptionDecryption: IO[String] = for {
          key1      <- S.generateKey
          encrypted <- E.encryptWithAADDetached(testPlainText, key1, aad1)
          decrypted <- E.decryptWithAADDetached(encrypted._1, key1, aad2, encrypted._2)
        } yield decrypted.toUtf8String
        if (!testMessage.isEmpty && !AAD1.isEmpty && !AAD2.isEmpty)
          testEncryptionDecryption.attempt.unsafeRunSync() mustNot equal(Right(testMessage))
      }
    }

    behavior of (spec + " Key Generator")

    it should "Not allow a key with incorrect length" in {
      val randomKey: Array[Byte] = (1 until 100).toArray.map(_ => Random.nextInt(128).toByte)
      val keyLenTest: IO[K[A]] = for {
        k <- S.build(randomKey)
      } yield k

      keyLenTest.attempt.unsafeRunSync() mustBe a[Left[_, _]]
    }
  }

}
