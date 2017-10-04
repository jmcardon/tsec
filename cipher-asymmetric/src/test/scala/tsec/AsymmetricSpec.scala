package tsec


import java.security.Security

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.scalatest.MustMatchers
import tsec.cipher.asymmetric.JCAAsymmetricCipher
import tsec.cipher.asymmetric.imports._
import tsec.cipher.common.{CipherError, CipherKeyBuildError, PlainText}
import tsec.cipher.common.padding.Padding
import tsec.cipher.asymmetric.core.JKeyPairGenerator

class AsymmetricSpec extends TestSpec with MustMatchers {

  if (Security.getProvider("BC") == null)
    Security.addProvider(new BouncyCastleProvider())


  def utf8String(array: Array[Byte]) = new String(array, "UTF-8")

  def arrayCompare(array1: Array[Byte], array2: Array[Byte]): Boolean =
    if (array1.length != array2.length)
      false
    else
      (array1 zip array2).forall(r => r._1 == r._2)

  def cipherTest[A, P](
                           implicit symm: AsymmetricAlgorithm[A],
                           keyGen: JKeyPairGenerator[A, KeyPair, CipherKeyBuildError],
                           p: Padding[P]
                         ): Unit = {

    val testMessage = "a" * 32
    val testPlainText: PlainText = PlainText(testMessage.getBytes("UTF-8"))

    val spec = s"""${symm.algorithm}_${symm.keyLength}/${p.algorithm}"""

    behavior of spec

    it should "Encrypt and decrypt for the same key" in {
      val testEncryptionDecryption: Either[CipherError, String] = for {
        instance <- JCAAsymmetricCipher[A, P]
        keyPair <- keyGen.generateKeyPair()
        encrypted <- instance.encrypt(testPlainText, keyPair.publicKey)
        decrypted <- instance.decrypt(encrypted, keyPair.privateKey)
      } yield utf8String(decrypted.content)

      testEncryptionDecryption.left.map(x => println(x.cause))
      testEncryptionDecryption mustBe Right(testMessage)
    }

    it should "not decrypt properly for an incorrect public key" in {
      val testEncryptionDecryption = for {
        instance <- JCAAsymmetricCipher[A, P]
        keyPair1 <- keyGen.generateKeyPair()
        keyPair2 <- keyGen.generateKeyPair()
        encrypted <- instance.encrypt(testPlainText, keyPair1.publicKey)
        decrypted <- instance.decrypt(encrypted, keyPair2.privateKey)
      } yield utf8String(decrypted.content)

      testEncryptionDecryption mustNot equal(Right(testMessage))
    }
  }

}
