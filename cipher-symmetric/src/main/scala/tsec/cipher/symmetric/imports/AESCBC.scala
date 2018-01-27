package tsec.cipher.symmetric.imports

import cats.effect.Sync
import tsec.cipher.common.padding.PKCS7Padding
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.core.IvStrategy
import tsec.cipher.symmetric.imports.primitive.JCAPrimitiveCipher

sealed abstract class AESCBCConstruction[A: AES] extends JCACipher[A, CBC, PKCS7Padding, CBCCipherText[A]] {
  def genEncryptor[F[_]: Sync]: F[CBCEncryptor[F, A]] = JCAPrimitiveCipher[F, A, CBC, PKCS7Padding]()

  def defaultIvStrategy: IvStrategy[A, CBC] = IvStrategy.defaultStrategy[A, CBC]

  def ciphertextFromArray(array: Array[Byte]): Either[CipherTextError, CipherText[A, CBC, PKCS7Padding]] =
    CipherText.fromArray[A, CBC, PKCS7Padding, SecretKey](array)
}

object AES128CBC extends AESCBCConstruction[AES128]

object AES192CBC extends AESCBCConstruction[AES192]

object AES256CBC extends AESCBCConstruction[AES256]
