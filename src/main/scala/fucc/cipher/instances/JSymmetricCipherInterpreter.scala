package fucc.cipher.instances

import javax.crypto.spec.IvParameterSpec
import javax.crypto.{Cipher => JCipher, SecretKey => JSecretKey}

import cats.syntax.either._
import com.softwaremill.tagging.@@
import fucc.cipher._
import fucc.cipher.core._

class JSymmetricCipherInterpreter[A, M, P](implicit algoTag: CipherAlgo[A],
                                           modeTag: CMode[M],
                                           paddingTag: Padding[P])
    extends CipherAlgebra[Either[CipherError, ?], A, M, P, JSecretKey @@ A] {

  type C = JCipher

  def genInstance: () => JCipher =
    () =>
      JCipher.getInstance(
        s"${algoTag.algorithm}/${modeTag.algorithm}/${paddingTag.algorithm}")

  def encrypt(clearText: PlainText[A, M, P],
              key: SecretKey[JSecretKey @@ A],
              encryptor: JCipher): Either[CipherError, CipherText[A, M, P]] = {
    for {
      init <- cipherErrorMap({
        encryptor.init(JCipher.ENCRYPT_MODE, key.key)
        encryptor
      })(EncryptError.apply)
      f <- cipherErrorMap(init.doFinal(clearText.content))(EncryptError.apply)
      iv <- Either.fromOption(Option(init.getIV), EncryptError("No IV found"))
    } yield CipherText(f, iv)
  }

  def decrypt(cipherText: CipherText[A, M, P],
              key: SecretKey[JSecretKey @@ A],
              decryptor: JCipher): Either[CipherError, PlainText[A, M, P]] = {
    for {
      init <- cipherErrorMap({
        decryptor.init(JCipher.DECRYPT_MODE,
                       key.key,
                       new IvParameterSpec(cipherText.iv))
        decryptor
      })(DecryptError.apply)
      decrypted <- cipherErrorMap(init.doFinal(cipherText.content))(
        DecryptError.apply)
    } yield PlainText(decrypted)
  }

  def cipherErrorMap[T](a: T)(
      errFun: String => CipherError): Either[CipherError, T] =
    Either.catchNonFatal(a).leftMap(e => errFun(e.getMessage))
}
