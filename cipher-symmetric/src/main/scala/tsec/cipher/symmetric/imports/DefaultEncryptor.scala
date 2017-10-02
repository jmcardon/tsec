package tsec.cipher.symmetric.imports

import tsec.cipher.common.mode.CTR
import tsec.cipher.common.padding.NoPadding
import tsec.cipher.common.{CipherKeyBuildError, NoSuchInstanceError}
import tsec.common.JKeyGenerator

sealed abstract class DefaultEncryptor[A: SymmetricAlgorithm] {
  def getInstance: Either[NoSuchInstanceError, JCASymmetricCipher[A, CTR, NoPadding]] =
    JCASymmetricCipher[A, CTR, NoPadding]

  @inline
  def keyGen(
      implicit keyGenerator: JKeyGenerator[A, SecretKey, CipherKeyBuildError]
  ): JKeyGenerator[A, SecretKey, CipherKeyBuildError] = keyGenerator
}

object DefaultEncryptor extends DefaultEncryptor[AES128]

object StrongEncryptor extends DefaultEncryptor[AES128]
