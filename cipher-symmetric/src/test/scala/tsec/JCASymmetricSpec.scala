package tsec

import cats.effect.IO
import org.scalatest.MustMatchers
import org.scalatest.prop.PropertyChecks
import tsec.cipher.common.padding._
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.jca._
import tsec.common._
import tsec.keygen.symmetric._

import scala.util.Random

class JCASymmetricSpec extends TestSpec with MustMatchers with PropertyChecks {

  final def cipherTest[A, M, P](algebra: JCACipherAPI[A, M, P] with SymmetricKeyGenAPI[A, SecretKey])(
      implicit symm: BlockCipher[A],
      mode: CipherMode[M],
      p: SymmetricPadding[P],
      ivProcess: IvProcess[A, M, P],
      S: SymmetricKeyGen[IO, A, SecretKey],
      E: Encryptor[IO, A, SecretKey]
  ): Unit = {

    val spec = s"""${symm.cipherName}_${symm.keySizeBytes * 8}/${mode.mode}/${p.algorithm}"""

    behavior of spec

    implicit val defaultStrat: IvGen[IO, A] = JCAIvGen.random[IO, A]

    it should "Encrypt and decrypt for the same key" in {
      forAll { (testMessage: String) =>
        val testPlainText = PlainText(testMessage.utf8Bytes)
        val testEncryptionDecryption: IO[String] = for {
          key       <- algebra.generateKey[IO]
          encrypted <- algebra.encrypt[IO](testPlainText, key)
          decrypted <- algebra.decrypt[IO](encrypted, key)
        } yield decrypted.toUtf8String
        testEncryptionDecryption.attempt.unsafeRunSync() must equal(Right(testMessage))
      }
    }

    it should "Be able to build a correct key from a repr" in {
      forAll { (testMessage: String) =>
        val testPlainText = PlainText(testMessage.utf8Bytes)
        val testEncryptionDecryption: IO[String] = for {
          key       <- algebra.generateKey[IO]
          encrypted <- algebra.encrypt[IO](testPlainText, key)
          keyRepr = key.getEncoded
          built     <- algebra.buildKey[IO](keyRepr)
          decrypted <- algebra.decrypt[IO](encrypted, built)
        } yield decrypted.toUtf8String
        testEncryptionDecryption.attempt.unsafeRunSync() must equal(Right(testMessage))
      }
    }

    it should "not decrypt properly for an incorrect key" in {
      forAll { (testMessage: String) =>
        val testPlainText = PlainText(testMessage.utf8Bytes)
        val testEncryptionDecryption: IO[String] = for {
          key1      <- algebra.generateKey[IO]
          key2      <- algebra.generateKey[IO]
          encrypted <- algebra.encrypt[IO](testPlainText, key1)
          decrypted <- algebra.decrypt[IO](encrypted, key2)
        } yield decrypted.toUtf8String
        if (!testMessage.isEmpty)
          testEncryptionDecryption.attempt.unsafeRunSync() mustNot equal(Right(testMessage))
      }
    }

    behavior of (spec + " Key Generator")

    it should "Not allow a key with incorrect length" in {
      val randomKey: Array[Byte] = (1 until 100).toArray.map(_ => Random.nextInt(128).toByte)
      val keyLenTest: IO[Boolean] = for {
        k <- algebra.buildKey[IO](randomKey)
      } yield k.getEncoded.length < randomKey.length

      keyLenTest.attempt.unsafeRunSync() mustBe a[Left[_, _]]
    }
  }

  final def authCipherTest[A, M, P](algebra: JCAAEAD[A, M, P] with SymmetricKeyGenAPI[A, SecretKey])(
      implicit symm: BlockCipher[A],
      aead: AEADCipher[A],
      mode: CipherMode[M],
      p: SymmetricPadding[P],
      ivProcess: IvProcess[A, M, P],
      S: SymmetricKeyGen[IO, A, SecretKey],
      E: AADEncryptor[IO, A, SecretKey]
  ): Unit = {

    val spec = s"""${symm.cipherName}_${symm.keySizeBytes * 8}/${mode.mode}/${p.algorithm}"""

    implicit val defaultStrat = JCAIvGen.random[IO, A]

    behavior of spec

    it should "Encrypt and decrypt for the same key" in {
      forAll { (testMessage: String) =>
        val testPlainText = PlainText(testMessage.utf8Bytes)
        val testEncryptionDecryption: IO[String] = for {
          key       <- algebra.generateKey[IO]
          encrypted <- algebra.encrypt[IO](testPlainText, key)
          decrypted <- algebra.decrypt[IO](encrypted, key)
        } yield decrypted.toUtf8String
        testEncryptionDecryption.attempt.unsafeRunSync() must equal(Right(testMessage))
      }
    }

    it should "Be able to build a correct key from a repr" in {
      forAll { (testMessage: String) =>
        val testPlainText = PlainText(testMessage.utf8Bytes)
        val testEncryptionDecryption: IO[String] = for {
          key       <- algebra.generateKey[IO]
          encrypted <- algebra.encrypt[IO](testPlainText, key)
          keyRepr = key.getEncoded
          built     <- algebra.buildKey[IO](keyRepr)
          decrypted <- algebra.decrypt[IO](encrypted, built)
        } yield decrypted.toUtf8String
        testEncryptionDecryption.attempt.unsafeRunSync() must equal(Right(testMessage))
      }
    }

    it should "Encrypt and decrypt for the same key and AEAD" in {
      forAll { (testMessage: String, aadData: String) =>
        val testPlainText = PlainText(testMessage.utf8Bytes)
        val aad           = AAD(aadData.utf8Bytes)
        val testEncryptionDecryption: IO[String] = for {
          key       <- algebra.generateKey[IO]
          encrypted <- algebra.encryptWithAAD[IO](testPlainText, key, aad)
          decrypted <- algebra.decryptWithAAD[IO](encrypted, key, aad)
        } yield decrypted.toUtf8String
        testEncryptionDecryption.attempt.unsafeRunSync() must equal(Right(testMessage))
      }
    }

    it should "not decrypt properly for an incorrect key" in {
      forAll { (testMessage: String) =>
        val testPlainText = PlainText(testMessage.utf8Bytes)
        val testEncryptionDecryption: IO[String] = for {
          key1      <- algebra.generateKey[IO]
          key2      <- algebra.generateKey[IO]
          encrypted <- algebra.encrypt[IO](testPlainText, key1)
          decrypted <- algebra.decrypt[IO](encrypted, key2)
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
          key1      <- algebra.generateKey[IO]
          encrypted <- algebra.encryptWithAAD[IO](testPlainText, key1, aad1)
          decrypted <- algebra.decryptWithAAD[IO](encrypted, key1, aad2)
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
          key       <- algebra.generateKey[IO]
          encrypted <- algebra.encryptDetached[IO](testPlainText, key)
          decrypted <- algebra.decryptDetached[IO](encrypted._1, key, encrypted._2)
        } yield decrypted.toUtf8String
        testEncryptionDecryption.attempt.unsafeRunSync() must equal(Right(testMessage))
      }
    }

    it should "Be able to build a correct key from a repr in detached mode" in {
      forAll { (testMessage: String) =>
        val testPlainText = PlainText(testMessage.utf8Bytes)
        val testEncryptionDecryption: IO[String] = for {
          key       <- algebra.generateKey[IO]
          encrypted <- algebra.encryptDetached[IO](testPlainText, key)
          keyRepr = key.getEncoded
          built     <- algebra.buildKey[IO](keyRepr)
          decrypted <- algebra.decryptDetached[IO](encrypted._1, built, encrypted._2)
        } yield decrypted.toUtf8String
        testEncryptionDecryption.attempt.unsafeRunSync() must equal(Right(testMessage))
      }
    }

    it should "Encrypt and decrypt for the same key and AEAD in detached mode" in {
      forAll { (testMessage: String, aadData: String) =>
        val testPlainText = PlainText(testMessage.utf8Bytes)
        val aad           = AAD(aadData.utf8Bytes)
        val testEncryptionDecryption: IO[String] = for {
          key       <- algebra.generateKey[IO]
          encrypted <- algebra.encryptWithAADDetached[IO](testPlainText, key, aad)
          decrypted <- algebra.decryptWithAADDetached[IO](encrypted._1, key, aad, encrypted._2)
        } yield decrypted.toUtf8String
        testEncryptionDecryption.attempt.unsafeRunSync() must equal(Right(testMessage))
      }
    }

    it should "not decrypt properly for an incorrect key in detached mode" in {
      forAll { (testMessage: String) =>
        val testPlainText = PlainText(testMessage.utf8Bytes)
        val testEncryptionDecryption: IO[String] = for {
          key1      <- algebra.generateKey[IO]
          key2      <- algebra.generateKey[IO]
          encrypted <- algebra.encryptDetached[IO](testPlainText, key1)
          decrypted <- algebra.decryptDetached[IO](encrypted._1, key2, encrypted._2)
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
          key1      <- algebra.generateKey[IO]
          encrypted <- algebra.encryptWithAADDetached[IO](testPlainText, key1, aad1)
          decrypted <- algebra.decryptWithAADDetached[IO](encrypted._1, key1, aad2, encrypted._2)
        } yield decrypted.toUtf8String
        if (!testMessage.isEmpty && !AAD1.isEmpty && !AAD2.isEmpty)
          testEncryptionDecryption.attempt.unsafeRunSync() mustNot equal(Right(testMessage))
      }
    }

    behavior of (spec + " Key Generator")

    it should "Not allow a key with incorrect length" in {
      val randomKey: Array[Byte] = (1 until 100).toArray.map(_ => Random.nextInt(128).toByte)
      val keyLenTest: IO[Boolean] = for {
        k <- algebra.buildKey[IO](randomKey)
      } yield k.getEncoded.length < randomKey.length

      keyLenTest.attempt.unsafeRunSync() mustBe a[Left[_, _]]
    }
  }

}
