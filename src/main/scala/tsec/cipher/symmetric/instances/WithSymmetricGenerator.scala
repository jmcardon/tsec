package tsec.cipher.symmetric.instances

import tsec.cipher.common.SecretKey
import tsec.core.JKeyGenerator

abstract class WithSymmetricGenerator[T](repr: String, keyLen: Int) {
  implicit val tag: SymmetricAlgorithm[T]                       = SymmetricAlgorithm[T](repr, keyLen)
  implicit val keyGen: JKeyGenerator[JEncryptionKey[T], SecretKey] = JSymmetricKeyGenerator.fromType[T](tag)
}
