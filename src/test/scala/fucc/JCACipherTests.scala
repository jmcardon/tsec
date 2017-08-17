package fucc

import org.scalatest.{Matchers, MustMatchers}
import tsec.cipher.common._
import tsec.cipher.common.mode._
import tsec.cipher.common.padding._
import tsec.cipher.symmetric.instances._
import tsec.core.JKeyGenerator

import scala.annotation.tailrec
import scala.util.Random

class JCACipherTests extends TestSpec with MustMatchers {

  def utf8String(array: Array[Byte]) = new String(array, "UTF-8")

  def arrayCompare(array1: Array[Byte], array2: Array[Byte]): Boolean =
    if (array1.length != array2.length)
      false
    else
      (array1 zip array2).forall(r => r._1 == r._2)

  def cipherTest[A: SymmetricAlgorithm, M: ModeKeySpec, P: Padding](
      spec: String
  )(implicit keyGen: JKeyGenerator[JEncryptionKey[A], SecretKey, CipherKeyBuildError]): Unit = {
    val testMessage                       = "The Moose is Loose"
    val testPlainText: PlainText[A, M, P] = PlainText[A, M, P](testMessage.getBytes("UTF-8"))

    behavior of spec

    it should "Encrypt and decrypt for the same key" in {
      val testEncryptionDecryption: Either[CipherError, String] = for {
        key       <- keyGen.generateKey()
        instance  <- JCASymmetricCipher.getCipher[A, M, P]
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
          key: SecretKey[JEncryptionKey[A]]
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
        instance <- JCASymmetricCipher.getCipher[A, M, P]
        first    <- instance.encrypt(testPlainText, key)
      } yield tailrecGenIVs(first, 100000, instance, key)

      testIvs mustBe Right(true)
    }

    it should "not decrypt properly for an incorrect key" in {
      val testEncryptionDecryption: Either[CipherError, String] = for {
        key1      <- keyGen.generateKey()
        key2      <- keyGen.generateKey()
        instance  <- JCASymmetricCipher.getCipher[A, M, P]
        encrypted <- instance.encrypt(testPlainText, key1)
        decrypted <- instance.decrypt(encrypted, key2)
      } yield new String(decrypted.content, "UTF-8")
      testEncryptionDecryption mustNot equal(Right(testMessage))

      behavior of (spec + " Key Generator")

      it should "Truncate a key longer than the max cipher keylength" in {
        val randomKey: Array[Byte] = (1 until 100).toArray.map(_ => Random.nextInt(128).toByte)
        val keyLenTest: Either[CipherKeyBuildError, Boolean] = for {
          k <- keyGen.buildKey(randomKey)
        } yield k.key.getEncoded.length < randomKey.length

        keyLenTest mustBe Right(true)
      }
    }
  }

  cipherTest[AES128, GCM, NoPadding]("AES128 GCM with no padding")
  cipherTest[AES256, GCM, NoPadding]("AES256 GCM wit no padding")
  cipherTest[GeneralAES, CBC, PKCS7Padding]("AES CBC with PKCS7Padding")
  cipherTest[GeneralAES, CTR, PKCS7Padding]("AES CTR with PKCS7Padding")

}
