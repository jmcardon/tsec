package tsec.cipher.asymmetric

import javax.crypto.{Cipher => JCipher}

import tsec.cipher.asymmetric.core.AsymmetricCipherAlgebra
import tsec.cipher.asymmetric.imports._
import tsec.cipher.common
import tsec.cipher.common._
import tsec.cipher.common.mode.{ModeKeySpec, NoMode}
import tsec.cipher.common.padding.Padding
import cats.syntax.either._
import tsec.common.ErrorConstruct._

class JCAAsymmetricCipher[A, P](implicit algoTag: AsymmetricAlgorithm[A], paddingTag: Padding[P])
    extends AsymmetricCipherAlgebra[Either[CipherError, ?], A, P] {

  type C = JCipher

  def genInstance =
    Either
      .catchNonFatal(JCipher.getInstance(s"${algoTag.algorithm}/None/${paddingTag.algorithm}", "BC"))
      .mapError(InstanceInitError.apply)

  protected[this] def initEncryptor(cipher: JCipher, publicKey: PublicKey[A]): Either[CipherKeyError, Unit] =
    Either
      .catchNonFatal(
        cipher.init(JCipher.ENCRYPT_MODE, publicKey)
      )
      .mapError(CipherKeyError.apply)

  protected[this] def initDecryptor(
      cipher: JCipher,
      publicKey: PrivateKey[A],
      iv: Array[Byte]
  ): Either[CipherKeyError, Unit] =
    Either
      .catchNonFatal(
        cipher.init(JCipher.DECRYPT_MODE, publicKey)
      )
      .mapError(CipherKeyError.apply)

  def encrypt(plainText: common.PlainText, privateKey: PublicKey[A]): Either[CipherError, CipherText[A, NoMode, P]] =
    for {
      instance <- genInstance
      _        <- initEncryptor(instance, privateKey)
      encrypted <- Either
        .catchNonFatal(instance.doFinal(plainText.content))
        .mapError(EncryptError.apply)
    } yield CipherText(encrypted,Array.empty)

  def decrypt(cipherText: CipherText[A, NoMode, P], key: PrivateKey[A]): Either[CipherError, PlainText] =
    for {
      instance <- genInstance
      _        <- initDecryptor(instance, key, cipherText.iv)
      decrypted <- Either
        .catchNonFatal(instance.doFinal(cipherText.content))
        .mapError(DecryptError.apply)
    } yield PlainText(decrypted)

}


object JCAAsymmetricCipher {
  def apply[A: AsymmetricAlgorithm, P: Padding] = {
   val c = new JCAAsymmetricCipher[A, P]
    c.genInstance.map(_ => c).leftMap(_ => NoSuchInstanceError)
  }
}