package tsec.symmetric.instances

import com.softwaremill.tagging._
import tsec.cipher.core.{CipherAlgo, CipherAlgorithm}
import tsec.core.CryptoTag
import tsec.symmetric.core.SymmetricKeyGenerator

abstract class WithSymmetricGenerator[T](repr: String) {
  implicit val tag: CipherAlgo[T] = CryptoTag.fromString[T](repr).taggedWith[CipherAlgorithm]
  implicit val keyGen: SymmetricKeyGenerator[JSymmetric[T]] = JSymmetricKeyGenerator.fromType[T](tag)
}

