package tsec.cipher.symmetric.imports

import cats.effect.Sync
import tsec.cipher.common.padding.PKCS7Padding
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.core._
import tsec.cipher.symmetric.imports.primitive._

sealed abstract class AESCBCConstruction[A] extends JCACipher[A, CBC, PKCS7Padding] {
  def encryptor[F[_]: Sync](implicit c: BlockCipher[A]): F[Encryptor[F, A, SecretKey]] =
    JCAPrimitiveCipher.sync[F, A, CBC, PKCS7Padding]()

  def defaultIvStrategy[F[_]: Sync](implicit c: BlockCipher[A]): IvGen[F, A] = JCAIvGen.random[F, A]

  @deprecated("use ciphertextFromConcat", "0.0.1-M10")
  def ciphertextFromArray(array: Array[Byte])(implicit a: AES[A]): Either[CipherTextError, CipherText[A]] =
    ciphertextFromConcat(array)

  def ciphertextFromConcat(rawCT: Array[Byte])(implicit a: AES[A]): Either[CipherTextError, CipherText[A]] =
    CTOPS.ciphertextFromArray[A, CBC, PKCS7Padding](rawCT)
}

sealed trait AES128CBC

object AES128CBC extends AESCBCConstruction[AES128CBC] with AES128[AES128CBC]

sealed trait AES192CBC

object AES192CBC extends AESCBCConstruction[AES192CBC] with AES192[AES192CBC]

sealed trait AES256CBC

object AES256CBC extends AESCBCConstruction[AES256CBC] with AES256[AES256CBC]
