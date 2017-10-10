package tsec.cipher.symmetric.imports

import tsec.cipher.common._
import tsec.cipher.common.mode.CTR
import tsec.cipher.common.padding.NoPadding


sealed abstract class Encryptor[A: SymmetricAlgorithm] {
  lazy val instance: Either[NoSuchInstanceError, JCASymmetricCipher[A, CTR, NoPadding]] =
    JCASymmetricCipher[A, CTR, NoPadding]

  @inline
  def keyGen(
      implicit keyGenerator: CipherKeyGen[A]
  ): CipherKeyGen[A] = keyGenerator

  def fromSingleArray(bytes: Array[Byte]): Either[CipherTextError, CipherText[A, CTR, NoPadding]] =
    CipherText.fromSingleArray[A, CTR, NoPadding](bytes)
}

object Encryptor {
  implicit val defaultEncryptor: Encryptor[AES128] = DefaultEncryptor
  implicit val strongEncryptor: Encryptor[AES256] = StrongEncryptor
}

object DefaultEncryptor extends Encryptor[AES128]

object StrongEncryptor extends Encryptor[AES256]
