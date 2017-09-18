package tsec.api

import tsec.cipher.common
import tsec.cipher.common._
import tsec.cipher.common.mode.GCM
import tsec.cipher.common.padding.NoPadding
import tsec.cipher.symmetric.instances._
import tsec.core.JKeyGenerator

abstract class DefaultEncryptor[A: SymmetricAlgorithm] {
  def default: Either[NoSuchInstanceError, JCASymmetricCipher[A, GCM, NoPadding]] =
    JCASymmetricCipher[A, GCM, NoPadding]

  def generateKey(
      implicit keyGen: JKeyGenerator[A, SecretKey, CipherKeyBuildError]
  ): Either[CipherKeyBuildError, SecretKey[A]] =
    keyGen.generateKey()

  def buildKey(
      keyBytes: Array[Byte]
  )(implicit keyGen: JKeyGenerator[A, SecretKey, CipherKeyBuildError]): Either[CipherKeyBuildError, SecretKey[A]] =
    keyGen.buildKey(keyBytes)
}

object DefaultEncryptor {
  object Default extends DefaultEncryptor[AES128]
  object Strong  extends DefaultEncryptor[AES256]
}
