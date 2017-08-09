package fucc.symmetric.instances

import com.softwaremill.tagging._
import fucc.cipher.core.{CipherAlgo, CipherAlgorithm}
import fucc.core.CryptoTag
import fucc.symmetric.core.SymmetricKeyGenerator

abstract class WithSymmetricGenerator[T](repr: String) {
  implicit val tag: CipherAlgo[T] = CryptoTag.fromString[T](repr).taggedWith[CipherAlgorithm]
  implicit val keyGen: SymmetricKeyGenerator[JSymmetric[T]] = JSymmetricKeyGenerator.fromType[T](tag)
}

