package tsec.cipher.symmetric.imports

import tsec.cipher.common._
import tsec.cipher.common.mode.GCM
import tsec.cipher.common.padding.NoPadding
import tsec.common.JKeyGenerator

sealed abstract class AuthEncryptor[A: SymmetricAlgorithm] {
  lazy val instance: Either[NoSuchInstanceError, JCASymmetricCipher[A, GCM, NoPadding]] =
    JCASymmetricCipher[A, GCM, NoPadding]

  @inline
  def keyGen(
      implicit keyGenerator: JKeyGenerator[A, SecretKey, CipherKeyBuildError]
  ): JKeyGenerator[A, SecretKey, CipherKeyBuildError] = keyGenerator

  def fromSingleArray(bytes: Array[Byte]): Either[CipherTextError, CipherText[A, GCM, NoPadding]] =
    CipherText.fromSingleArray[A, GCM, NoPadding](bytes)
}

object DefaultAuthEncryptor extends AuthEncryptor[AES128] {
  implicit val encryptor: AuthEncryptor[AES128] = this
}

object MediumAuthEncryptor extends AuthEncryptor[AES192] {
  implicit val encryptor: AuthEncryptor[AES192] = this
}

object StrongAuthEncryptor extends AuthEncryptor[AES256] {
  implicit val encryptor: AuthEncryptor[AES256] = this
}
