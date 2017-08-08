package fucc.cipher

//import cats.instances.either
import cats.syntax.either._

import java.security.SecureRandom
import javax.crypto.spec.IvParameterSpec
import javax.crypto.{SecretKey, Cipher => JCipher}

object instance {

  val `DES/ECB/PKCS5Padding` = new Cipher[DES, ECB, `PKCS5Padding`] {

    def generator = JCipher.getInstance(s"${DES.tag.algorithm}/${ECB.tag.algorithm}/${`PKCS5Padding`.tag.algorithm}")
    def getIV(): Array[Byte] = List(0,0,0,0,0,0,0,0).map(_.toByte).toArray

    override def encrypt(clearText: ClearText)(implicit key: SecretKey): Either[CipherError, CipherText] = {
      val gen = generator

     gen.init(JCipher.ENCRYPT_MODE, key , new IvParameterSpec(getIV()))
      CipherText(gen.doFinal(clearText.content)).asRight[EncryptError]
    }

    override def decrypt(cipherText: CipherText)(implicit key: SecretKey): Either[CipherError, ClearText] = {
      val gen = generator

      gen.init(JCipher.DECRYPT_MODE,  key, new IvParameterSpec(getIV()))
      ClearText(gen.doFinal(cipherText.content)).asRight[DecryptError]
    }
  }

}
