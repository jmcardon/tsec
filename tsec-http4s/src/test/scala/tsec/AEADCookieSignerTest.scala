package tsec

import cats.effect.IO
import org.scalatest.MustMatchers
import org.scalatest.prop.PropertyChecks
import tsec.cipher.common.padding.NoPadding
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.imports._
import tsec.cipher.symmetric.imports.primitive.JCAAEADPrimitive
import tsec.cookies.AEADCookieEncryptor

class AEADCookieSignerTest extends TestSpec with MustMatchers with PropertyChecks {

  def aeadCookieTest[A](implicit cipher: AES[A], keyGen: CipherKeyGen[A]) = {
    implicit val strategy = GCM.randomIVStrategy[A]

    implicit val instance = JCAAEADPrimitive[IO, A, GCM, NoPadding]().unsafeRunSync()

    behavior of s"AEAD Cookie encrypting with ${cipher.cipherName}${cipher.keySizeBytes * 8}"

    it should "Encrypt and decrypt properly" in {
      val now = java.time.Instant.now().toString
      forAll { (s: String) =>
        val encryptDecrypt = for {
          key       <- keyGen.generateLift[IO]
          encrypted <- AEADCookieEncryptor.signAndEncrypt[IO, A](s, AAD.buildFromStringUTF8(now), key)
          decrypted <- AEADCookieEncryptor.retrieveFromSigned[IO, A](encrypted, key)
        } yield decrypted

        if (s.isEmpty)
          encryptDecrypt.attempt.unsafeRunSync() mustBe Left(EncryptError("Cannot encrypt an empty string!"))
        else
          encryptDecrypt.attempt.unsafeRunSync() mustBe Right(s)
      }
    }

    it should "not encrypt and decrypt properly with an incorrect key" in {
      val now = java.time.Instant.now().toString
      forAll { (s: String) =>
        val encryptDecrypt = for {
          key       <- keyGen.generateLift[IO]
          key2      <- keyGen.generateLift[IO]
          encrypted <- AEADCookieEncryptor.signAndEncrypt[IO, A](s, AAD.buildFromStringUTF8(now), key)
          decrypted <- AEADCookieEncryptor.retrieveFromSigned[IO, A](encrypted, key2)
        } yield decrypted

        if (s.isEmpty)
          encryptDecrypt.attempt.unsafeRunSync() mustBe Left(EncryptError("Cannot encrypt an empty string!"))
        else
          encryptDecrypt.attempt.unsafeRunSync() mustBe a[Left[CipherError, _]]
      }
    }
  }

  aeadCookieTest[AES128]
  aeadCookieTest[AES192]
  aeadCookieTest[AES256]
}
