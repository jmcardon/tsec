package tsec.cipher.symmetric.instances

import tsec.cipher.common._
import tsec.cipher.common.mode.GCM
import tsec.cipher.common.padding.NoPadding
import tsec.core.JKeyGenerator

sealed abstract class DefaultAuthEncryptor[A: SymmetricAlgorithm] {
  def getInstance: Either[NoSuchInstanceError, JCASymmetricCipher[A, GCM, NoPadding]] =
    JCASymmetricCipher[A, GCM, NoPadding]

  @inline def keyGen(
      implicit keyGenerator: JKeyGenerator[A, SecretKey, CipherKeyBuildError]
  ): JKeyGenerator[A, SecretKey, CipherKeyBuildError] = keyGenerator
}

object DefaultAuthEncryptor extends DefaultAuthEncryptor[AES128]

object StrongAuthEncryptor extends DefaultAuthEncryptor[AES256]
