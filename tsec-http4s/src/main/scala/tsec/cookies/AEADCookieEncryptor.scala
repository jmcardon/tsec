package tsec.cookies

import tsec.common._
import tsec.cipher.common._
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.imports._

object AEADCookieEncryptor {

  def signAndEncrypt[A](message: String, aad: AAD, key: SecretKey[A])(
      implicit authEncryptor: AuthEncryptor[A]
  ): Either[CipherError, AEADCookie[A]] =
    if (message.isEmpty)
      Left(EncryptError("Cannot encrypt an empty string!"))
    else
      for {
        instance  <- authEncryptor.instance
        encrypted <- instance.encryptAAD(PlainText(message.utf8Bytes), key, aad)
      } yield AEADCookie.fromEncrypted[A](encrypted, aad)

  def retrieveFromSigned[A](message: AEADCookie[A], key: SecretKey[A])(
      implicit authEncryptor: AuthEncryptor[A]
  ): Either[CipherError, String] = {
    val split = message.split("-")
    if (split.length != 2)
      Left(DecryptError("Could not decode cookie"))
    else {
      val aad = AAD(split(1).base64Bytes)
      for {
        instance   <- authEncryptor.instance
        cipherText <- authEncryptor.fromSingleArray(split(0).base64Bytes)
        decrypted  <- instance.decryptAAD(cipherText, key, aad)
      } yield decrypted.content.toUtf8String
    }
  }

}
