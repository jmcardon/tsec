package tsec

import org.scalatest.MustMatchers
import org.scalatest.prop.PropertyChecks
import tsec.cipher.common._
import tsec.cipher.symmetric.imports._
import tsec.cookies.AEADCookieEncryptor

class AEADCookieSignerTest extends TestSpec with MustMatchers with PropertyChecks {

  def aeadCookieTest[A: CipherKeyGen](implicit authE: AuthEncryptor[A], s: SymmetricAlgorithm[A]) = {
    behavior of s"AEAD Cookie encrypting with ${s.algorithm}${s.keyLength}"

    it should "Encrypt and decrypt properly" in {
      val now = java.time.Instant.now().toString
      forAll { (s: String) =>
        val encryptDecrypt = for {
          key <- authE.keyGen.generateKey()
          encrypted <- AEADCookieEncryptor.signAndEncrypt[A](s, AAD.buildFromStringUTF8(now),key)
          decrypted <- AEADCookieEncryptor.retrieveFromSigned[A](encrypted, key)
        } yield decrypted

        if(s.isEmpty)
          encryptDecrypt mustBe Left(EncryptError("Cannot encrypt an empty string!"))
        else
          encryptDecrypt mustBe Right(s)
      }
    }

    it should "not encrypt and decrypt properly with an incorrect key" in {
      val now = java.time.Instant.now().toString
      forAll { (s: String) =>
        val encryptDecrypt = for {
          key <- authE.keyGen.generateKey()
          key2 <- authE.keyGen.generateKey()
          encrypted <- AEADCookieEncryptor.signAndEncrypt[A](s, AAD.buildFromStringUTF8(now),key)
          decrypted <- AEADCookieEncryptor.retrieveFromSigned[A](encrypted, key2)
        } yield decrypted

        if(s.isEmpty)
          encryptDecrypt mustBe Left(EncryptError("Cannot encrypt an empty string!"))
        else
          encryptDecrypt mustBe a[Left[CipherError, _]]
      }
    }
  }

  aeadCookieTest[AES128]
  aeadCookieTest[AES192]
  aeadCookieTest[AES256]
}
