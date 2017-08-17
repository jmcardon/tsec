package fucc

import javax.crypto.Cipher

import org.scalatest.Matchers
import tsec.cipher.common._
import tsec.cipher.common.mode._
import tsec.cipher.common.padding._
import tsec.cipher.symmetric.instances._

class JCACipherTests extends TestSpec with Matchers {

  def cipherTest[A: SymmetricAlgorithm, M: ModeKeySpec, P: Padding](spec: String,w: WithSymmetricGenerator[A]): Unit ={
    spec should "Encrypt and decrypt for the same key" in {
      val tt = "The Moose is Loose"
      val testMessage = PlainText[A, M, P](tt.getBytes("UTF-8"))
      val testie = for {
        key <- w.keyGen.generateKey()
        instance <- JCASymmetricCipher.getCipher[A, M, P]
        encrypted <- instance.encrypt(testMessage, key)
        decrypted <- instance.decrypt(encrypted, key)
      } yield new String(decrypted.content, "UTF-8")

      testie should equal(Right(tt))
    }
  }

  cipherTest[AES128, GCM, NoPadding]("AES128 GCM with no padding", AES128)
  cipherTest[GeneralAES, CBC, PKCS7Padding]("AES CBC with PKCS7Padding", GeneralAES)
  cipherTest[GeneralAES, CTR, PKCS7Padding]("AES CTR with PKCS7Padding", GeneralAES)
  cipherTest[AES256, GCM, NoPadding]("AES256 GCM wit no padding", AES256)

  JCASymmetricCipher.getCipherUnsafe[GeneralAES, GeneralAES, GeneralAES]

}
