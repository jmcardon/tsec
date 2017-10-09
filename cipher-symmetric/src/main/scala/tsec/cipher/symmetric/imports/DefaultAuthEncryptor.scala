package tsec.cipher.symmetric.imports

import tsec.cipher.common._
import tsec.cipher.common.mode.GCM
import tsec.cipher.common.padding.NoPadding

sealed abstract class AuthEncryptor[A: SymmetricAlgorithm] {
  lazy val instance: Either[NoSuchInstanceError, JCASymmetricCipher[A, GCM, NoPadding]] =
    JCASymmetricCipher[A, GCM, NoPadding]

  @inline
  def keyGen(
      implicit keyGenerator: CipherKeyGen[A]
  ): CipherKeyGen[A] = keyGenerator

  def fromSingleArray(bytes: Array[Byte]): Either[CipherTextError, AEADCipherText[A]] =
    CipherText.fromSingleArray[A, GCM, NoPadding](bytes)
}

object AuthEncryptor {
  implicit val e1: AuthEncryptor[AES128] = DefaultAuthEncryptor
  implicit val e2: AuthEncryptor[AES192] = MediumAuthEncryptor
  implicit val e3: AuthEncryptor[AES256] = StrongAuthEncryptor
}

object DefaultAuthEncryptor extends AuthEncryptor[AES128]

object MediumAuthEncryptor extends AuthEncryptor[AES192]

object StrongAuthEncryptor extends AuthEncryptor[AES256]
