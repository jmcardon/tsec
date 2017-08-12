package tsec.symmetric.instances

import tsec.symmetric.core.{SymmetricAlgorithm, SymmetricKeyGenerator}

abstract class WithSymmetricGenerator[T](repr: String, keyLen: Int) {
  implicit val tag: SymmetricAlgorithm[T]                       = SymmetricAlgorithm[T](repr, keyLen)
  implicit val keyGen: SymmetricKeyGenerator[JEncryptionKey[T]] = JSymmetricKeyGenerator.fromType[T](tag)
}
