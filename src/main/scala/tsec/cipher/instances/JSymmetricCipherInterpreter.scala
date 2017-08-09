package tsec.cipher.instances

import javax.crypto.{Cipher => JCipher}
import cats.syntax.either._
import tsec.cipher.core._
import tsec.symmetric.instances.JEncryptionKey

class JSymmetricCipherInterpreter[A, M, P](
    implicit algoTag: CipherAlgo[A],
    modeTag: CMode[M],
    modeSpec: ModeKeySpec[M],
    paddingTag: Padding[P]
) extends CipherAlgebra[Either[CipherError, ?], A, M, P, JEncryptionKey[A]] {

  type C = JCipher

  def genInstance: () => JCipher =
    () => JCipher.getInstance(s"${algoTag.algorithm}/${modeTag.algorithm}/${paddingTag.algorithm}")

  def encrypt(
      clearText: PlainText[A, M, P],
      key: SecretKey[JEncryptionKey[A]],
      encryptor: JCipher
  ): Either[CipherError, CipherText[A, M, P]] =
    for {
      init <- Either
        .catchNonFatal({
          //Unfortunately we must side effect here, but it is local
          encryptor.init(JCipher.ENCRYPT_MODE, key.key)
          encryptor
        })
        .leftMap(e => EncryptError(e.getMessage))
      f  <- Either.catchNonFatal(init.doFinal(clearText.content)).leftMap(e => EncryptError(e.getMessage))
      iv <- Either.fromOption(Option(init.getIV), EncryptError("No IV found"))
    } yield CipherText(f, iv)

  def decrypt(
      cipherText: CipherText[A, M, P],
      key: SecretKey[JEncryptionKey[A]],
      decryptor: JCipher
  ): Either[CipherError, PlainText[A, M, P]] =
    for {
      init <- Either
        .catchNonFatal({
          decryptor.init(JCipher.DECRYPT_MODE, key.key, modeSpec.buildAlgorithmSpec(cipherText.iv))
          decryptor
        })
        .leftMap(e => DecryptError(e.getMessage))
      decrypted <- Either.catchNonFatal(init.doFinal(cipherText.content)).leftMap(e => DecryptError(e.getMessage))
    } yield PlainText(decrypted)

}
