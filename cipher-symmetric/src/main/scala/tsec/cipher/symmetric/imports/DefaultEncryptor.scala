package tsec.cipher.symmetric.imports

import tsec.cipher.symmetric._
import tsec.cipher.common.padding.NoPadding

sealed abstract class Encryptor[A: SymmetricCipher] {
  lazy val instance: Either[NoSuchInstanceError, JCASymmCipherImpure[A, CTR, NoPadding]] =
    JCASymmCipherImpure[A, CTR, NoPadding]

  @inline
  def keyGen(
      implicit keyGenerator: CipherKeyGen[A]
  ): CipherKeyGen[A] = keyGenerator

  def fromSingleArray(bytes: Array[Byte]): Either[CipherTextError, CipherText[A, CTR, NoPadding]] =
    CipherText.fromSingleArray[A, CTR, NoPadding](bytes)
}

object Encryptor {
  implicit val defaultEncryptor: Encryptor[AES128] = DefaultEncryptor
  implicit val strongEncryptor: Encryptor[AES256]  = StrongEncryptor
}

object DefaultEncryptor extends Encryptor[AES128]

object StrongEncryptor extends Encryptor[AES256]
