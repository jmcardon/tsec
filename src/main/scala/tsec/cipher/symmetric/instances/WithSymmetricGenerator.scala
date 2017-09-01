package tsec.cipher.symmetric.instances

import tsec.cipher.common.CipherKeyBuildError
import tsec.core.JKeyGenerator

protected[tsec] abstract class WithSymmetricGenerator[T](repr: String, keyLen: Int) {
  implicit val tag: SymmetricAlgorithm[T] = SymmetricAlgorithm[T](repr, keyLen)
  implicit val keyGen: JKeyGenerator[T, SecretKey, CipherKeyBuildError] =
    JSymmetricKeyGenerator.fromType[T](tag)
}